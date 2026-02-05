"""Support for Siedle door locks."""
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
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
    """Set up Siedle locks from config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][entry.entry_id]["api"]

    contacts = coordinator.data.get("contacts", [])
    entities = [
        SiedleLock(coordinator, api, entry, contact) for contact in contacts
    ]

    async_add_entities(entities)


class SiedleLock(CoordinatorEntity, LockEntity):
    """Representation of a Siedle door lock."""

    def __init__(self, coordinator, api, entry, contact):
        """Initialize the lock."""
        super().__init__(coordinator)
        self._api = api
        self._contact = contact
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{contact['id']}"
        self._attr_name = f"Siedle {contact.get('name', 'Door')}"
        self._attr_is_locked = True

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
            "contact_type": self._contact.get("type"),
        }

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the door (open it)."""
        _LOGGER.info("Unlocking door %s", self._contact["id"])
        await self.hass.async_add_executor_job(
            self._api.openDoor, self._contact["id"]
        )
        self._attr_is_locked = True
        self.async_write_ha_state()

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the door (not supported)."""
        _LOGGER.warning("Locking not supported for Siedle doors")
