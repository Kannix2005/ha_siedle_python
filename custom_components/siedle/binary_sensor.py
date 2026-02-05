"""Support for Siedle binary sensors (doorbell, etc.)."""
import logging
from datetime import datetime, timedelta

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.event import async_track_point_in_time
import homeassistant.util.dt as dt_util

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# How long the doorbell binary sensor stays "on" after a ring
DOORBELL_ON_DURATION = timedelta(seconds=5)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle binary sensors from config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][entry.entry_id]["api"]
    
    entities = [
        SiedleDoorbellSensor(coordinator, entry, hass),
        SiedleMQTTConnectedSensor(coordinator, entry),
    ]
    
    # Add a sensor for each door contact
    contacts = await hass.async_add_executor_job(api.get_contacts, "DOOR", False)
    for contact in contacts:
        entities.append(
            SiedleDoorContactSensor(coordinator, entry, contact)
        )
    
    async_add_entities(entities)


class SiedleDoorbellSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor that triggers when the doorbell is pressed.
    
    This sensor listens to FCM push notifications and MQTT events
    and turns "on" briefly when a doorbell ring is detected.
    """

    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY  # or SOUND
    _attr_has_entity_name = True
    
    def __init__(self, coordinator, entry, hass: HomeAssistant):
        """Initialize the doorbell sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._hass = hass
        self._attr_unique_id = f"{entry.entry_id}_doorbell"
        self._attr_name = "Türklingel"
        self._attr_icon = "mdi:bell-ring"
        self._is_on = False
        self._last_ring = None
        self._unsub_timer = None
        
        # Register callbacks for FCM and MQTT events
        self._hass.bus.async_listen(
            f"{DOMAIN}_doorbell",
            self._handle_doorbell_event
        )
        self._hass.bus.async_listen(
            f"{DOMAIN}_event",
            self._handle_siedle_event
        )

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Siedle Türstation",
            "manufacturer": "Siedle",
            "model": self.coordinator.data.get("status", {}).get("config", {}).get("deviceType", "SUS"),
            "sw_version": self.coordinator.data.get("status", {}).get("config", {}).get("deviceVersion"),
        }

    @property
    def is_on(self):
        """Return true if the doorbell was recently pressed."""
        return self._is_on

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return {
            "last_ring": self._last_ring.isoformat() if self._last_ring else None,
        }

    @callback
    def _handle_doorbell_event(self, event):
        """Handle doorbell event from FCM."""
        if event.data.get("entry_id") != self._entry.entry_id:
            return
        
        _LOGGER.info("Doorbell event received!")
        self._trigger_doorbell()

    @callback
    def _handle_siedle_event(self, event):
        """Handle generic Siedle event (MQTT or FCM)."""
        if event.data.get("entry_id") != self._entry.entry_id:
            return
        
        event_type = event.data.get("type")
        
        # Check for doorbell-related events
        if event_type == "fcm":
            fcm_type = event.data.get("event_type", "").lower()
            if fcm_type in ["doorbell", "call", "storycall"]:
                _LOGGER.info(f"FCM doorbell event: {fcm_type}")
                self._trigger_doorbell()
        
        elif event_type == "mqtt":
            topic = event.data.get("topic", "").lower()
            if any(x in topic for x in ['call', 'ring', 'doorbell', 'bell', 'klingel']):
                _LOGGER.info(f"MQTT doorbell event on topic: {topic}")
                self._trigger_doorbell()

    @callback
    def _trigger_doorbell(self):
        """Trigger the doorbell sensor."""
        self._is_on = True
        self._last_ring = dt_util.utcnow()
        self.async_write_ha_state()
        
        # Cancel any existing timer
        if self._unsub_timer:
            self._unsub_timer()
        
        # Set timer to turn off the sensor
        self._unsub_timer = async_track_point_in_time(
            self._hass,
            self._turn_off,
            dt_util.utcnow() + DOORBELL_ON_DURATION
        )
        
        _LOGGER.info("Doorbell sensor triggered!")

    @callback
    def _turn_off(self, now):
        """Turn off the doorbell sensor after timeout."""
        self._is_on = False
        self._unsub_timer = None
        self.async_write_ha_state()
        _LOGGER.debug("Doorbell sensor turned off")


class SiedleMQTTConnectedSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor showing MQTT connection status."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_has_entity_name = True
    
    def __init__(self, coordinator, entry):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_mqtt_connected"
        self._attr_name = "MQTT Verbindung"
        self._attr_icon = "mdi:server-network"

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Siedle Türstation",
            "manufacturer": "Siedle",
        }

    @property
    def is_on(self):
        """Return true if MQTT is connected."""
        return self.coordinator.data.get("mqtt_connected", False)


class SiedleDoorContactSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for individual door contact (online/available)."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_has_entity_name = True
    
    def __init__(self, coordinator, entry, contact: dict):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._contact = contact
        self._contact_id = contact.get("id")
        
        # Use s_name or id for unique_id
        name_base = contact.get("s_name", contact.get("id", "unknown"))[:20]
        self._attr_unique_id = f"{entry.entry_id}_contact_{self._contact_id}"
        self._attr_name = f"Türkontakt {contact.get('phone', {}).get('callNumber', 'Unbekannt')}"
        self._attr_icon = "mdi:door"

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Siedle Türstation",
            "manufacturer": "Siedle",
        }

    @property
    def is_on(self):
        """Return true if the door contact is available."""
        # Find this contact in the coordinator data
        contacts = self.coordinator.data.get("contacts", [])
        for contact in contacts:
            if contact.get("id") == self._contact_id:
                # Check if doorOpener is available
                return contact.get("doorOpener") is not None
        return False

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return {
            "contact_id": self._contact_id,
            "call_number": self._contact.get("phone", {}).get("callNumber"),
            "callable": self._contact.get("phone", {}).get("callable"),
            "has_camera": self._contact.get("camera") is not None,
            "has_door_opener": self._contact.get("doorOpener") is not None,
            "has_door_light": self._contact.get("doorLight") is not None,
        }
