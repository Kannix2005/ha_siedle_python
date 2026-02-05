"""Button entities for Siedle integration."""
import logging
from homeassistant.components.button import ButtonEntity, ButtonDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle buttons from config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    api = data["api"]
    sip_manager = data.get("sip_manager")
    
    entities = []
    
    # Always add door opener button
    entities.append(SiedleDoorOpenerButton(entry, api))
    
    # Always add light button
    entities.append(SiedleLightButton(entry, api))
    
    # Add hangup button if SIP manager is available
    if sip_manager:
        entities.append(SiedleHangupButton(entry, sip_manager))
    
    # Add call door button if SIP manager is available
    if sip_manager:
        entities.append(SiedleCallDoorButton(entry, sip_manager))
    
    async_add_entities(entities)


class SiedleButtonBase(ButtonEntity):
    """Base class for Siedle buttons."""
    
    _attr_has_entity_name = True
    _button_key: str = ""  # Override in subclasses
    
    def __init__(self, entry: ConfigEntry):
        """Initialize button."""
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{self._button_key}"
    
    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Siedle {self._entry.data.get('endpoint_id', 'Unknown')[:8]}",
            manufacturer="Siedle",
            model="Smart Gateway",
        )


class SiedleDoorOpenerButton(SiedleButtonBase):
    """Button to open the door."""
    
    _attr_name = "Tür öffnen"
    _attr_icon = "mdi:door-open"
    _button_key = "door_opener"
    
    def __init__(self, entry: ConfigEntry, api):
        """Initialize door opener button."""
        super().__init__(entry)
        self._api = api
    
    async def async_press(self) -> None:
        """Handle button press."""
        _LOGGER.info("Door opener button pressed")
        await self.hass.async_add_executor_job(self._api.openDoor)


class SiedleLightButton(SiedleButtonBase):
    """Button to toggle door light."""
    
    _attr_name = "Licht"
    _attr_icon = "mdi:lightbulb"
    _button_key = "door_light"
    
    def __init__(self, entry: ConfigEntry, api):
        """Initialize light button."""
        super().__init__(entry)
        self._api = api
    
    async def async_press(self) -> None:
        """Handle button press."""
        _LOGGER.info("Door light button pressed")
        await self.hass.async_add_executor_job(self._api.turnOnLight)


class SiedleHangupButton(SiedleButtonBase):
    """Button to hang up active call."""
    
    _attr_name = "Auflegen"
    _attr_icon = "mdi:phone-hangup"
    _attr_device_class = ButtonDeviceClass.RESTART  # Closest match for "action"
    _button_key = "hangup"
    
    def __init__(self, entry: ConfigEntry, sip_manager):
        """Initialize hangup button."""
        super().__init__(entry)
        self._sip_manager = sip_manager
    
    async def async_press(self) -> None:
        """Handle button press."""
        _LOGGER.info("Hangup button pressed")
        await self.hass.async_add_executor_job(self._sip_manager.hangup)
    
    @property
    def available(self) -> bool:
        """Return if button is available (call is active)."""
        if self._sip_manager:
            return self._sip_manager.is_call_active
        return False


class SiedleCallDoorButton(SiedleButtonBase):
    """Button to initiate call to door station."""
    
    _attr_name = "Türstation anrufen"
    _attr_icon = "mdi:phone-outgoing"
    _button_key = "call_door"
    
    def __init__(self, entry: ConfigEntry, sip_manager):
        """Initialize call door button."""
        super().__init__(entry)
        self._sip_manager = sip_manager
    
    async def async_press(self) -> None:
        """Handle button press."""
        _LOGGER.info("Call door button pressed")
        # TODO: Implement call to door station
        # This would require SIP INVITE to the door station
        pass
    
    @property
    def available(self) -> bool:
        """Return if button is available (no active call)."""
        if self._sip_manager:
            return not self._sip_manager.is_call_active
        return True
