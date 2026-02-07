"""Support for Siedle sensors."""
import logging
import os
from collections import deque
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import (
    DOMAIN,
    CALL_STATE_IDLE,
    CALL_STATE_RINGING,
    CALL_STATE_CONNECTED,
    CALL_STATE_RECORDING,
    CONF_RECORDING_PATH,
    DEFAULT_RECORDING_PATH,
    CONF_CALL_HISTORY_SIZE,
    DEFAULT_CALL_HISTORY_SIZE,
    SIGNAL_SIEDLE_CONNECTION_UPDATE,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle sensors from config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    sip_manager = data.get("sip_manager")

    entities = [
        SiedleMQTTStatusSensor(coordinator, entry),
        SiedleSIPStatusSensor(coordinator, entry),
    ]
    
    # Add call status sensor if SIP manager available
    if sip_manager:
        entities.append(SiedleCallStatusSensor(entry, sip_manager, hass))
    
    # Add last recording sensor
    entities.append(SiedleLastRecordingSensor(entry, hass))
    
    # Add call history sensor (F4)
    call_history_sensor = SiedleCallHistorySensor(entry, hass)
    entities.append(call_history_sensor)
    
    # Store reference for updates from __init__.py
    data["call_history_sensor"] = call_history_sensor

    async_add_entities(entities)


class SiedleSensorBase(SensorEntity):
    """Base class for Siedle sensors."""
    
    _attr_has_entity_name = True
    
    def __init__(self, entry: ConfigEntry):
        """Initialize sensor."""
        self._entry = entry
    
    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Siedle {self._entry.data.get('endpoint_id', 'Unknown')[:8]}",
            manufacturer="Siedle",
            model="Smart Gateway",
        )


class SiedleMQTTStatusSensor(CoordinatorEntity, SensorEntity):
    """Sensor for MQTT connection status."""

    _attr_has_entity_name = True
    _attr_name = "MQTT Status"
    _attr_icon = "mdi:access-point-network"

    def __init__(self, coordinator, entry):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_mqtt_status"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Siedle {self._entry.data.get('endpoint_id', 'Unknown')[:8]}",
            manufacturer="Siedle",
            model="Smart Gateway",
        )

    async def async_added_to_hass(self) -> None:
        """Register dispatcher listener for immediate updates."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_SIEDLE_CONNECTION_UPDATE, self._handle_connection_update
            )
        )

    @callback
    def _handle_connection_update(self) -> None:
        """Handle connection state change — update immediately."""
        self.async_write_ha_state()

    @property
    def native_value(self):
        """Return the state of the sensor — read live from API."""
        api = self.hass.data.get(DOMAIN, {}).get(self._entry.entry_id, {}).get("api")
        if api:
            return "Verbunden" if api.mqtt_connected else "Getrennt"
        return self.coordinator.data.get("mqtt_connected", False) and "Verbunden" or "Getrennt"

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        api = self.hass.data.get(DOMAIN, {}).get(self._entry.entry_id, {}).get("api")
        connected = api.mqtt_connected if api else self.coordinator.data.get("mqtt_connected", False)
        return {
            "mqtt_connected": connected,
        }


class SiedleSIPStatusSensor(CoordinatorEntity, SensorEntity):
    """Sensor for SIP connection status."""

    _attr_has_entity_name = True
    _attr_name = "SIP Status"
    _attr_icon = "mdi:phone-voip"

    def __init__(self, coordinator, entry):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_sip_status"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Siedle {self._entry.data.get('endpoint_id', 'Unknown')[:8]}",
            manufacturer="Siedle",
            model="Smart Gateway",
        )

    async def async_added_to_hass(self) -> None:
        """Register dispatcher listener for immediate updates."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_SIEDLE_CONNECTION_UPDATE, self._handle_connection_update
            )
        )

    @callback
    def _handle_connection_update(self) -> None:
        """Handle connection state change — update immediately."""
        self.async_write_ha_state()

    @property
    def native_value(self):
        """Return the state of the sensor — read live from SIP manager."""
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry.entry_id, {})
        sip_manager = entry_data.get("sip_manager")
        api = entry_data.get("api")
        
        sip_registered = False
        ext_sip_registered = False
        
        if sip_manager:
            if hasattr(sip_manager, '_siedle_conn') and sip_manager._siedle_conn:
                sip_registered = sip_manager._siedle_conn.registered
            if hasattr(sip_manager, '_external_conn') and sip_manager._external_conn:
                ext_sip_registered = sip_manager._external_conn.registered
        
        # Fallback to API property
        if not sip_registered and api:
            sip_registered = api.sip_registered
        
        if sip_registered and ext_sip_registered:
            return "Beide verbunden"
        elif sip_registered:
            return "Siedle verbunden"
        elif ext_sip_registered:
            return "Extern verbunden"
        return "Getrennt"

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry.entry_id, {})
        sip_manager = entry_data.get("sip_manager")
        api = entry_data.get("api")
        
        sip_registered = False
        ext_sip_registered = False
        
        if sip_manager:
            if hasattr(sip_manager, '_siedle_conn') and sip_manager._siedle_conn:
                sip_registered = sip_manager._siedle_conn.registered
            if hasattr(sip_manager, '_external_conn') and sip_manager._external_conn:
                ext_sip_registered = sip_manager._external_conn.registered
        
        if not sip_registered and api:
            sip_registered = api.sip_registered
        
        return {
            "siedle_sip_registered": sip_registered,
            "external_sip_registered": ext_sip_registered,
        }


class SiedleCallStatusSensor(SiedleSensorBase):
    """Sensor showing current call status."""
    
    _attr_name = "Anrufstatus"
    _attr_icon = "mdi:phone"
    
    def __init__(self, entry: ConfigEntry, sip_manager, hass: HomeAssistant):
        """Initialize call status sensor."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_call_status"
        self._sip_manager = sip_manager
        self._hass = hass
        self._call_info = {}
        
        # Register for state changes
        if sip_manager:
            sip_manager.set_on_call_state_change(self._on_state_change)
    
    def _on_state_change(self, state, data):
        """Handle call state changes."""
        self._call_info = data
        # Schedule state update in HA event loop (thread-safe)
        if self._hass:
            self._hass.add_job(self.async_write_ha_state)
    
    @property
    def native_value(self) -> str:
        """Return current call state."""
        if not self._sip_manager:
            return CALL_STATE_IDLE
        
        state = self._sip_manager.state
        
        # Map to German
        state_map = {
            CALL_STATE_IDLE: "Bereit",
            CALL_STATE_RINGING: "Klingelt",
            CALL_STATE_CONNECTED: "Verbunden",
            CALL_STATE_RECORDING: "Aufnahme",
        }
        
        return state_map.get(state.value, state.value)
    
    @property
    def icon(self) -> str:
        """Return icon based on state."""
        if not self._sip_manager:
            return "mdi:phone"
        
        state = self._sip_manager.state.value
        icons = {
            CALL_STATE_IDLE: "mdi:phone",
            CALL_STATE_RINGING: "mdi:phone-ring",
            CALL_STATE_CONNECTED: "mdi:phone-in-talk",
            CALL_STATE_RECORDING: "mdi:record-rec",
        }
        return icons.get(state, "mdi:phone")
    
    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        attrs = {
            "call_active": self._sip_manager.is_call_active if self._sip_manager else False,
        }
        attrs.update(self._call_info)
        return attrs


class SiedleLastRecordingSensor(SiedleSensorBase):
    """Sensor showing last doorbell recording."""
    
    _attr_name = "Letzte Aufnahme"
    _attr_icon = "mdi:microphone"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    
    def __init__(self, entry: ConfigEntry, hass: HomeAssistant):
        """Initialize last recording sensor."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_last_recording"
        self._hass = hass
        self._last_recording_path: str | None = None
        self._last_recording_time: datetime | None = None
    
    def update_recording(self, filepath: str):
        """Update with new recording."""
        self._last_recording_path = filepath
        self._last_recording_time = datetime.now()
        # Schedule state update in HA event loop (thread-safe)
        if self._hass:
            self._hass.add_job(self.async_write_ha_state)
    
    @property
    def native_value(self):
        """Return timestamp of last recording."""
        return self._last_recording_time
    
    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        attrs = {}
        
        if self._last_recording_path:
            attrs["filepath"] = self._last_recording_path
            
            # Check if file exists and get size
            if os.path.exists(self._last_recording_path):
                size = os.path.getsize(self._last_recording_path)
                attrs["filesize"] = f"{size / 1024:.1f} KB"
                
                # Generate media URL for playback
                # Files in www/ are accessible via /local/
                recording_path = self._entry.options.get(CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH)
                if recording_path.startswith("www/"):
                    relative = self._last_recording_path.split("www/")[-1]
                    attrs["media_url"] = f"/local/{relative}"
        
        return attrs


class SiedleCallHistorySensor(SiedleSensorBase):
    """Sensor tracking call history with metadata (F4)."""
    
    _attr_name = "Anruf-Historie"
    _attr_icon = "mdi:phone-log"
    
    def __init__(self, entry: ConfigEntry, hass: HomeAssistant):
        """Initialize call history sensor."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_call_history"
        self._hass = hass
        max_size = entry.options.get(CONF_CALL_HISTORY_SIZE, DEFAULT_CALL_HISTORY_SIZE)
        self._history: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._current_call: dict[str, Any] | None = None
    
    def start_call(self, data: dict[str, Any]) -> None:
        """Record start of a new call (doorbell ring)."""
        self._current_call = {
            "timestamp": datetime.now().isoformat(),
            "from": data.get("from", ""),
            "caller_id": data.get("caller_id", ""),
            "call_id": data.get("call_id", ""),
            "source": data.get("source", "sip"),
            "answered": False,
            "duration_seconds": 0,
            "recording_file": None,
            "dtmf_door_opened": False,
        }
        self._current_call["_start_time"] = datetime.now()
        if self._hass:
            self._hass.add_job(self.async_write_ha_state)
    
    def call_answered(self, data: dict[str, Any] | None = None) -> None:
        """Mark current call as answered."""
        if self._current_call:
            self._current_call["answered"] = True
            if data and "recording_file" in data:
                self._current_call["recording_file"] = data["recording_file"]
            if self._hass:
                self._hass.add_job(self.async_write_ha_state)
    
    def call_ended(self, data: dict[str, Any] | None = None) -> None:
        """Record end of current call."""
        if self._current_call:
            start_time = self._current_call.pop("_start_time", None)
            if start_time:
                duration = (datetime.now() - start_time).total_seconds()
                self._current_call["duration_seconds"] = round(duration, 1)
            
            if data and "recording_file" in data:
                self._current_call["recording_file"] = data["recording_file"]
            if data and "dtmf_door_opened" in data:
                self._current_call["dtmf_door_opened"] = data["dtmf_door_opened"]
            
            self._history.append(self._current_call)
            self._current_call = None
            
            if self._hass:
                self._hass.add_job(self.async_write_ha_state)
    
    @property
    def native_value(self) -> int:
        """Return total number of calls in history."""
        return len(self._history)
    
    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return call history as attributes."""
        attrs: dict[str, Any] = {
            "total_calls": len(self._history),
            "calls_today": self._count_calls_today(),
        }
        
        # Last 10 calls (newest first)
        last_calls = list(self._history)[-10:]
        last_calls.reverse()
        attrs["last_calls"] = last_calls
        
        # Current call info
        if self._current_call:
            attrs["active_call"] = {
                k: v for k, v in self._current_call.items()
                if not k.startswith("_")
            }
        
        return attrs
    
    def _count_calls_today(self) -> int:
        """Count calls from today."""
        today = datetime.now().date().isoformat()
        return sum(
            1 for call in self._history
            if call.get("timestamp", "").startswith(today)
        )
    
    def get_history(self) -> list[dict[str, Any]]:
        """Get full call history (for diagnostics)."""
        return list(self._history)
