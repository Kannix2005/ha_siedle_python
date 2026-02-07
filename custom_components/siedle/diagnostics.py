"""Diagnostics support for Siedle integration."""
from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.redact import async_redact_data

from .const import DOMAIN

# Sensitive fields to redact
TO_REDACT_DATA = {
    "shared_secret",
    "token",
    "transfer_secret",
    "password",
    "setupKey",
    "endpointSetupKey",
    "access_token",
    "refresh_token",
}

TO_REDACT_OPTIONS = {
    DOMAIN + "_" + k for k in [
        "ext_sip_password",
        "fritzbox_password",
    ]
} | {
    "ext_sip_password",
    "fritzbox_password",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    
    sip_manager = entry_data.get("sip_manager")
    rtp_bridge = entry_data.get("rtp_bridge")
    api = entry_data.get("api")
    fcm_handler = entry_data.get("fcm_handler")
    coordinator = entry_data.get("coordinator")
    
    # SIP Manager Status
    sip_info: dict[str, Any] = {"available": False}
    if sip_manager:
        sip_info = {
            "available": True,
            "state": sip_manager.state.value,
            "is_call_active": sip_manager.is_call_active,
            "forward_to_number": sip_manager.forward_to_number,
            "forward_from_number": sip_manager.forward_from_number,
            "auto_answer": sip_manager.auto_answer,
            "recording_enabled": sip_manager.recording_enabled,
        }
        
        if hasattr(sip_manager, '_siedle_conn') and sip_manager._siedle_conn:
            conn = sip_manager._siedle_conn
            sip_info["siedle_connection"] = {
                "registered": conn.registered,
                "connected": conn.connected,
                "connection_lost": conn.connection_lost,
                "external_ip": conn.external_ip,
                "external_port": conn.external_port,
                "host": conn.config.host,
                "port": conn.config.port,
                "transport": conn.config.transport.value,
            }
        
        if hasattr(sip_manager, '_external_conn') and sip_manager._external_conn:
            conn = sip_manager._external_conn
            sip_info["external_connection"] = {
                "registered": conn.registered,
                "connected": conn.connected,
                "connection_lost": conn.connection_lost,
                "external_ip": conn.external_ip,
                "host": conn.config.host,
                "port": conn.config.port,
                "transport": conn.config.transport.value,
            }
    
    # RTP Bridge Status
    rtp_info: dict[str, Any] = {"available": False}
    if rtp_bridge:
        rtp_info = {
            "available": True,
            "is_recording": rtp_bridge.is_recording,
            "stats": rtp_bridge.stats,
            "local_port_a": rtp_bridge.local_port_a,
            "local_port_b": rtp_bridge.local_port_b,
        }
    
    # API / MQTT Status
    api_info: dict[str, Any] = {"available": False}
    if api:
        api_info = {
            "available": True,
            "mqtt_connected": api.mqtt_connected if hasattr(api, 'mqtt_connected') else None,
            "sip_registered": api.sip_registered if hasattr(api, 'sip_registered') else None,
            "endpoint_id": entry.data.get("endpoint_id", "unknown"),
        }
    
    # FCM Status
    fcm_info: dict[str, Any] = {"available": False}
    if fcm_handler:
        fcm_info = {
            "available": True,
            "is_connected": fcm_handler.is_connected if hasattr(fcm_handler, 'is_connected') else None,
        }
    
    # Coordinator data
    coordinator_data: dict[str, Any] = {}
    if coordinator and coordinator.data:
        data = coordinator.data
        coordinator_data = {
            "mqtt_connected": data.get("mqtt_connected"),
            "sip_registered": data.get("sip_registered"),
            "ext_sip_registered": data.get("ext_sip_registered"),
            "call_state": data.get("call_state"),
            "contacts_count": len(data.get("contacts", [])),
        }
    
    # Call History
    call_history = entry_data.get("call_history", [])
    
    return {
        "config_entry": {
            "data": async_redact_data(dict(entry.data), TO_REDACT_DATA),
            "options": async_redact_data(dict(entry.options), TO_REDACT_OPTIONS),
        },
        "sip_manager": sip_info,
        "rtp_bridge": rtp_info,
        "api": api_info,
        "fcm": fcm_info,
        "coordinator": coordinator_data,
        "call_history_count": len(call_history),
        "call_history_last_5": list(call_history)[-5:] if call_history else [],
    }
