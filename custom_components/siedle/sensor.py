"""Support for Siedle sensors."""
import logging
import os
from datetime import datetime

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    CALL_STATE_IDLE,
    CALL_STATE_RINGING,
    CALL_STATE_CONNECTED,
    CALL_STATE_RECORDING,
    CONF_RECORDING_PATH,
    DEFAULT_RECORDING_PATH,
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

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return "Verbunden" if self.coordinator.data.get("mqtt_connected") else "Getrennt"

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return {
            "mqtt_connected": self.coordinator.data.get("mqtt_connected", False),
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

    @property
    def native_value(self):
        """Return the state of the sensor."""
        data = self.coordinator.data or {}
        sip_registered = data.get("sip_registered", False)
        ext_sip_registered = data.get("ext_sip_registered", False)
        
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
        data = self.coordinator.data or {}
        return {
            "siedle_sip_registered": data.get("sip_registered", False),
            "external_sip_registered": data.get("ext_sip_registered", False),
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
        self.async_write_ha_state()
    
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
        self.async_write_ha_state()
    
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
