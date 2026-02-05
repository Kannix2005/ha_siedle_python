"""Support for Siedle door lights."""
import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle switches from config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][entry.entry_id]["api"]

    contacts = coordinator.data.get("contacts", [])
    entities = [
        SiedleLightSwitch(coordinator, api, entry, contact) for contact in contacts
    ]

    async_add_entities(entities)


class SiedleLightSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a Siedle door light."""

    def __init__(self, coordinator, api, entry, contact):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._contact = contact
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{contact['id']}_light"
        self._attr_name = f"Siedle {contact.get('name', 'Door')} Light"
        self._attr_is_on = False
        self._attr_icon = "mdi:lightbulb"

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Siedle Door System",
            "manufacturer": "Siedle",
            "model": "SUS",
        }

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return {
            "contact_id": self._contact["id"],
            "contact_name": self._contact.get("name"),
        }

    async def async_turn_on(self, **kwargs):
        """Turn the light on."""
        _LOGGER.info("Turning on light for door %s", self._contact["id"])
        await self.hass.async_add_executor_job(
            self._api.turnOnLight, self._contact["id"]
        )
        self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the light off."""
        _LOGGER.info("Turning off light for door %s", self._contact["id"])
        await self.hass.async_add_executor_job(
            self._api.turnOnLight, self._contact["id"]
        )
        self._attr_is_on = False
        self.async_write_ha_state()

    async def async_toggle(self, **kwargs):
        """Toggle the light."""
        if self._attr_is_on:
            await self.async_turn_off()
        else:
            await self.async_turn_on()
