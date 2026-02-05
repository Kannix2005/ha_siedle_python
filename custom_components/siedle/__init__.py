"""The Siedle integration."""
import asyncio
import logging
import os
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.components.http import HomeAssistantView

from .const import (
    DOMAIN,
    SERVICE_OPEN_DOOR,
    SERVICE_TOGGLE_LIGHT,
    SERVICE_HANGUP,
    ATTR_CONTACT_ID,
    CONF_EXT_SIP_ENABLED,
    CONF_EXT_SIP_HOST,
    CONF_EXT_SIP_PORT,
    CONF_EXT_SIP_USERNAME,
    CONF_EXT_SIP_PASSWORD,
    CONF_EXT_SIP_TRANSPORT,
    CONF_FORWARD_ENABLED,
    CONF_FORWARD_TO_NUMBER,
    CONF_FORWARD_FROM_NUMBER,
    CONF_AUTO_ANSWER,
    CONF_RECORDING_ENABLED,
    CONF_RECORDING_DURATION,
    CONF_RECORDING_PATH,
    DEFAULT_EXT_SIP_PORT,
    DEFAULT_EXT_SIP_TRANSPORT,
    DEFAULT_RECORDING_DURATION,
    DEFAULT_RECORDING_PATH,
)
from .siedle_api import Siedle

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.LOCK, Platform.SWITCH, Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Siedle component."""
    hass.data.setdefault(DOMAIN, {})
    
    # Register QR callback API endpoint only once
    if not any(isinstance(view, SiedleQRCallbackView) for view in hass.http.app.router._resources):
        _LOGGER.info("Registering Siedle QR callback view at /api/siedle/qr_callback")
        hass.http.register_view(SiedleQRCallbackView())
    else:
        _LOGGER.info("Siedle QR callback view already registered")
    
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up Siedle from a config entry."""
    setup_info = entry.data.get("setup_info")
    token = entry.data.get("token")
    setup_data = entry.data.get("setup_data")
    shared_secret = entry.data.get("shared_secret")  # Decrypted secret (hex string)
    endpoint_id = entry.data.get("endpoint_id")
    transfer_secret = entry.data.get("transfer_secret")

    # Initialize Siedle API
    try:
        # Use cached token if available, otherwise authorize
        if token and setup_data:
            _LOGGER.info("Using cached token from config entry")
            siedle = await hass.async_add_executor_job(
                lambda: Siedle(
                    token=token,
                    token_cache_file=hass.config.path(f".siedle_token_{entry.entry_id}.json"),
                )
            )
            # Restore setupData, endpoint_id, transferSecret, and DECRYPTED sharedSecret
            siedle._setupData = setup_data
            siedle._endpoint_id = endpoint_id
            siedle._transferSecret = transfer_secret
            # Restore decrypted sharedSecret (critical for door/light control!)
            if shared_secret:
                siedle._sharedSecret = bytes.fromhex(shared_secret)
                _LOGGER.info("Restored decrypted sharedSecret from config entry")
            else:
                _LOGGER.warning("No sharedSecret in config - door/light control may not work!")
            # Load config and contacts
            await hass.async_add_executor_job(siedle._load_config)
            await hass.async_add_executor_job(siedle._load_contacts)
        else:
            _LOGGER.info("No cached token, authorizing with setup info")
            siedle = await hass.async_add_executor_job(
                lambda: Siedle(
                    setupInfo=setup_info,
                    token_cache_file=hass.config.path(f".siedle_token_{entry.entry_id}.json"),
                )
            )
    except Exception as err:
        _LOGGER.error("Failed to setup Siedle: %s", err)
        raise ConfigEntryNotReady from err

    # Setup data coordinator
    coordinator = SiedleDataUpdateCoordinator(hass, siedle)
    await coordinator.async_config_entry_first_refresh()

    # Store coordinator
    hass.data[DOMAIN][entry.entry_id] = {
        "api": siedle,
        "coordinator": coordinator,
        "sip_manager": None,
        "rtp_bridge": None,
        "last_recording_sensor": None,
    }

    # ============== Setup SIP Call Manager ==============
    sip_manager = None
    rtp_bridge = None
    
    if entry.options.get("enable_sip", True):
        try:
            from .sip_manager import SipCallManager, SipConfig, SipTransport
            from .rtp_handler import RtpBridge
            
            # Get Siedle SIP credentials
            sip_creds = await hass.async_add_executor_job(siedle.get_sip_credentials)
            
            if sip_creds:
                siedle_sip_config = SipConfig.from_dict(sip_creds)
                
                # Check for external SIP configuration
                external_sip_config = None
                if entry.options.get(CONF_EXT_SIP_ENABLED, False):
                    ext_host = entry.options.get(CONF_EXT_SIP_HOST)
                    if ext_host:
                        transport_str = entry.options.get(CONF_EXT_SIP_TRANSPORT, DEFAULT_EXT_SIP_TRANSPORT)
                        external_sip_config = SipConfig(
                            host=ext_host,
                            port=entry.options.get(CONF_EXT_SIP_PORT, DEFAULT_EXT_SIP_PORT),
                            username=entry.options.get(CONF_EXT_SIP_USERNAME, ""),
                            password=entry.options.get(CONF_EXT_SIP_PASSWORD, ""),
                            transport=SipTransport(transport_str),
                            display_name="Siedle Türstation",
                        )
                        _LOGGER.info(f"External SIP configured: {ext_host}")
                
                # Get forwarding settings
                forward_enabled = entry.options.get(CONF_FORWARD_ENABLED, False)
                forward_to = entry.options.get(CONF_FORWARD_TO_NUMBER) if forward_enabled else None
                forward_from = entry.options.get(CONF_FORWARD_FROM_NUMBER) if forward_enabled else None
                auto_answer = entry.options.get(CONF_AUTO_ANSWER, False)
                
                # Create SIP Call Manager
                sip_manager = SipCallManager(
                    siedle_config=siedle_sip_config,
                    external_config=external_sip_config,
                    forward_to_number=forward_to,
                    forward_from_number=forward_from,
                    auto_answer=auto_answer,
                )
                
                # Create RTP Bridge
                rtp_bridge = RtpBridge()
                sip_manager.rtp_bridge = rtp_bridge
                
                # Set callbacks
                sip_manager.set_on_doorbell(
                    lambda data: _sip_doorbell_callback(hass, entry, data, sip_manager, rtp_bridge)
                )
                sip_manager.set_on_call_state_change(
                    lambda state, data: _sip_state_callback(hass, entry, state, data)
                )
                
                # Start SIP manager in background
                await hass.async_add_executor_job(sip_manager.start)
                
                hass.data[DOMAIN][entry.entry_id]["sip_manager"] = sip_manager
                hass.data[DOMAIN][entry.entry_id]["rtp_bridge"] = rtp_bridge
                
                _LOGGER.info("SIP Call Manager started successfully")
            else:
                _LOGGER.warning("No SIP credentials available - using legacy SIP listener")
                # Fallback to old SIP listener
                await hass.async_add_executor_job(
                    siedle.start_sip_listener,
                    lambda event_type, data: _sip_callback(hass, entry, event_type, data)
                )
                
        except Exception as e:
            _LOGGER.error(f"Failed to start SIP Call Manager: {e}")
            _LOGGER.exception(e)
            # Fallback to basic SIP listener
            try:
                await hass.async_add_executor_job(
                    siedle.start_sip_listener,
                    lambda event_type, data: _sip_callback(hass, entry, event_type, data)
                )
            except:
                pass

    # Setup platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Start MQTT if enabled (for device status)
    if entry.options.get("enable_mqtt", True):
        await hass.async_add_executor_job(
            siedle.connect_mqtt, 
            lambda topic, payload: _mqtt_callback(hass, entry, topic, payload)
        )

    # Start FCM Push listener if enabled (fallback for doorbell events)
    # Note: May not work due to protobuf compatibility issues
    if entry.options.get("enable_fcm", False):  # Disabled by default
        fcm_credentials_file = hass.config.path(f".siedle_fcm_{entry.entry_id}.json")
        await hass.async_add_executor_job(
            siedle.start_fcm_listener,
            lambda event_type, data: _fcm_callback(hass, entry, event_type, data),
            fcm_credentials_file
        )

    # Register services
    await async_setup_services(hass, siedle)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        data = hass.data[DOMAIN][entry.entry_id]
        api = data["api"]
        sip_manager = data.get("sip_manager")
        rtp_bridge = data.get("rtp_bridge")
        
        # Stop SIP Call Manager
        if sip_manager:
            await hass.async_add_executor_job(sip_manager.stop)
        
        # Stop RTP Bridge
        if rtp_bridge:
            await hass.async_add_executor_job(rtp_bridge.stop)
        
        # Disconnect MQTT
        await hass.async_add_executor_job(api.disconnect_mqtt)
        
        # Stop legacy SIP listener (if used)
        await hass.async_add_executor_job(api.stop_sip_listener)
        
        # Stop FCM listener
        await hass.async_add_executor_job(api.stop_fcm_listener)
        
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


def _mqtt_callback(hass: HomeAssistant, entry: ConfigEntry, topic: str, payload: dict):
    """Handle MQTT messages."""
    _LOGGER.debug("MQTT message: %s - %s", topic, payload)
    
    # Fire event for automations
    hass.bus.fire(
        f"{DOMAIN}_event",
        {
            "type": "mqtt",
            "topic": topic,
            "payload": payload,
            "entry_id": entry.entry_id,
        },
    )


def _sip_callback(hass: HomeAssistant, entry: ConfigEntry, event_type: str, data: dict):
    """Handle SIP doorbell events - THIS IS THE MAIN DOORBELL DETECTION!"""
    _LOGGER.info("🔔 SIP DOORBELL event: type=%s, data=%s", event_type, data)
    
    # Fire event for automations
    hass.bus.fire(
        f"{DOMAIN}_event",
        {
            "type": "sip",
            "event_type": event_type,
            "from": data.get("from", ""),
            "call_id": data.get("call_id", ""),
            "entry_id": entry.entry_id,
        },
    )
    
    # Fire specific doorbell event
    if event_type == "doorbell":
        hass.bus.fire(
            f"{DOMAIN}_doorbell",
            {
                "source": "sip",
                "from": data.get("from", ""),
                "call_id": data.get("call_id", ""),
                "entry_id": entry.entry_id,
            },
        )


def _sip_doorbell_callback(hass: HomeAssistant, entry: ConfigEntry, data: dict, 
                           sip_manager, rtp_bridge):
    """
    Handle doorbell events from new SIP Call Manager.
    This callback is called when an INVITE is received from Siedle (doorbell ring).
    """
    _LOGGER.info("🔔🔔🔔 DOORBELL! From: %s", data.get("from", "unknown"))
    
    # Fire HA event
    hass.bus.fire(
        f"{DOMAIN}_doorbell",
        {
            "source": "sip",
            "from": data.get("from", ""),
            "call_id": data.get("call_id", ""),
            "caller_id": data.get("caller_id", ""),
            "caller_host": data.get("caller_host", ""),
            "entry_id": entry.entry_id,
        },
    )
    
    # Start recording if enabled
    if entry.options.get(CONF_RECORDING_ENABLED, False):
        recording_path = entry.options.get(CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH)
        recording_duration = entry.options.get(CONF_RECORDING_DURATION, DEFAULT_RECORDING_DURATION)
        
        # Build full path
        full_path = hass.config.path(recording_path, "doorbell")
        
        try:
            # Ensure directory exists
            os.makedirs(full_path, exist_ok=True)
            
            # Start recording
            filepath = rtp_bridge.start_recording(
                os.path.join(full_path, "doorbell"),
                duration=recording_duration
            )
            _LOGGER.info(f"Recording started: {filepath}")
            
            # Update recording sensor
            entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
            recording_sensor = entry_data.get("last_recording_sensor")
            if recording_sensor:
                recording_sensor.update_recording(filepath)
                
        except Exception as e:
            _LOGGER.error(f"Failed to start recording: {e}")


def _sip_state_callback(hass: HomeAssistant, entry: ConfigEntry, state, data: dict):
    """Handle SIP call state changes."""
    _LOGGER.info("SIP call state changed: %s - %s", state.value if hasattr(state, 'value') else state, data)
    
    # Fire event for automations
    hass.bus.fire(
        f"{DOMAIN}_call_state",
        {
            "state": state.value if hasattr(state, 'value') else str(state),
            "data": data,
            "entry_id": entry.entry_id,
        },
    )


def _fcm_callback(hass: HomeAssistant, entry: ConfigEntry, event_type: str, data: dict):
    """Handle FCM push notifications."""
    _LOGGER.info("FCM event: type=%s, data=%s", event_type, data)
    
    # Fire event for automations
    hass.bus.fire(
        f"{DOMAIN}_event",
        {
            "type": "fcm",
            "event_type": event_type,
            "title": data.get("title", ""),
            "body": data.get("body", ""),
            "entry_id": entry.entry_id,
        },
    )
    
    # Also fire a specific doorbell event for easier automation
    if event_type == "doorbell":
        hass.bus.fire(
            f"{DOMAIN}_doorbell",
            {
                "title": data.get("title", ""),
                "body": data.get("body", ""),
                "entry_id": entry.entry_id,
            },
        )


async def async_setup_services(hass: HomeAssistant, siedle: Siedle):
    """Setup Siedle services."""
    async def handle_open_door(call):
        """Handle open door service call."""
        contact_id = call.data.get(ATTR_CONTACT_ID)
        await hass.async_add_executor_job(siedle.openDoor, contact_id)

    async def handle_toggle_light(call):
        """Handle toggle light service call."""
        contact_id = call.data.get(ATTR_CONTACT_ID)
        await hass.async_add_executor_job(siedle.turnOnLight, contact_id)
    
    async def handle_activate_endpoint(call):
        """Handle activate endpoint service call."""
        _LOGGER.info("Endpoint activation requested - press the doorbell button now!")
        await hass.async_add_executor_job(siedle.activate_endpoint)

    async def handle_hangup(call):
        """Handle hangup call service."""
        # Find the SIP manager from any entry
        for entry_id, data in hass.data.get(DOMAIN, {}).items():
            if isinstance(data, dict) and "sip_manager" in data:
                sip_manager = data.get("sip_manager")
                if sip_manager and sip_manager.is_call_active:
                    await hass.async_add_executor_job(sip_manager.hangup)
                    _LOGGER.info("Call hung up via service")
                    return
        _LOGGER.warning("No active call to hang up")

    hass.services.async_register(DOMAIN, SERVICE_OPEN_DOOR, handle_open_door)
    hass.services.async_register(DOMAIN, SERVICE_TOGGLE_LIGHT, handle_toggle_light)
    hass.services.async_register(DOMAIN, "activate_endpoint", handle_activate_endpoint)
    hass.services.async_register(DOMAIN, SERVICE_HANGUP, handle_hangup)


class SiedleDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching Siedle data."""

    def __init__(self, hass: HomeAssistant, api: Siedle):
        """Initialize."""
        self.api = api
        self.hass = hass
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=5),
        )

    async def _async_update_data(self):
        """Update data via library."""
        try:
            # Get contacts and status
            contacts = await self.hass.async_add_executor_job(self.api.get_contacts)
            status = await self.hass.async_add_executor_job(self.api.getStatus)
            
            # Get SIP manager status if available
            sip_registered = False
            ext_sip_registered = False
            call_state = "idle"
            
            # Find entry for this API
            for entry_id, data in self.hass.data.get(DOMAIN, {}).items():
                if isinstance(data, dict) and data.get("api") == self.api:
                    sip_manager = data.get("sip_manager")
                    if sip_manager:
                        if hasattr(sip_manager, '_siedle_conn') and sip_manager._siedle_conn:
                            sip_registered = sip_manager._siedle_conn.registered
                        if hasattr(sip_manager, '_external_conn') and sip_manager._external_conn:
                            ext_sip_registered = sip_manager._external_conn.registered
                        if hasattr(sip_manager, 'state'):
                            call_state = sip_manager.state.value
                    break
            
            return {
                "contacts": contacts,
                "status": status,
                "mqtt_connected": self.api.mqtt_connected,
                "sip_registered": sip_registered or self.api.sip_registered,
                "ext_sip_registered": ext_sip_registered,
                "call_state": call_state,
            }
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")


class SiedleQRCallbackView(HomeAssistantView):
    """Handle QR code callback from external scanner."""

    url = "/api/siedle/qr_callback"
    name = "api:siedle:qr_callback"
    requires_auth = False

    async def get(self, request):
        """Handle GET request from QR scanner redirect."""
        from aiohttp import web
        
        # Get parameters
        config_flow_id = request.query.get("config_flow_id")
        result = request.query.get("result")

        if not config_flow_id or not result:
            return web.Response(
                text="Missing parameters. Please try again.",
                status=400
            )

        # Get the config flow manager
        hass = request.app["hass"]
        
        try:
            # Continue the flow with the QR data - external step erwartet user_input
            await hass.config_entries.flow.async_configure(
                flow_id=config_flow_id,
                user_input={"result": result}
            )
            
            # Redirect to Home Assistant config flow UI
            return web.Response(
                text="""
                <html>
                <head>
                    <title>Siedle QR Code Success</title>
                    <script>
                        // Versuche das Fenster zu schließen und zu Home Assistant zurückzukehren
                        setTimeout(function() {
                            window.close();
                            // Falls close nicht funktioniert, redirecte zu HA
                            if (!window.closed) {
                                window.location.href = '/';
                            }
                        }, 2000);
                    </script>
                </head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>✅ QR Code erfolgreich gescannt!</h1>
                    <p>Die Konfiguration wird fortgesetzt...</p>
                    <p>Dieses Fenster schließt sich automatisch.</p>
                </body>
                </html>
                """,
                content_type="text/html"
            )
                
        except Exception as err:
            _LOGGER.error("Error processing QR callback: %s", err)
            return web.Response(
                text=f"Error processing QR code: {err}",
                status=500
            )

