"""Switch entities for Siedle integration."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle switches from config entry."""
    sip_manager = hass.data[DOMAIN][entry.entry_id].get("sip_manager")
    if sip_manager:
        async_add_entities([SiedleForwardingSwitch(entry, sip_manager)])


class SiedleForwardingSwitch(SwitchEntity, RestoreEntity):
    """Turns call forwarding on and off at runtime.

    Changing the options reloads the whole integration, and a doorbell ring
    during the reload can get lost. This switch only changes what the SIP
    manager looks at when the doorbell rings.
    """

    _attr_has_entity_name = True
    _attr_name = "Weiterleitung"
    _attr_icon = "mdi:phone-forward"

    def __init__(self, entry: ConfigEntry, sip_manager):
        """Initialize forwarding switch."""
        self._entry = entry
        self._sip_manager = sip_manager
        self._attr_unique_id = f"{entry.entry_id}_forwarding"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"Siedle {self._entry.data.get('endpoint_id', 'Unknown')[:8]}",
            manufacturer="Siedle",
            model="Smart Gateway",
        )

    @property
    def available(self) -> bool:
        """Forwarding needs a target number from the options."""
        return bool(self._sip_manager.configured_forward_to_number)

    @property
    def is_on(self) -> bool:
        """Return True if doorbell calls are forwarded."""
        return bool(self._sip_manager.forward_to_number)

    async def async_added_to_hass(self) -> None:
        """Restore the last state; the SIP manager starts with the option's value."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state and last_state.state in ("on", "off"):
            await self._async_set(last_state.state == "on")

    async def _async_set(self, enabled: bool) -> None:
        await self.hass.async_add_executor_job(
            self._sip_manager.set_forwarding_enabled, enabled
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Forward doorbell calls."""
        if not self.available:
            raise HomeAssistantError("No forwarding target number configured")
        await self._async_set(True)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        """Stop forwarding doorbell calls."""
        await self._async_set(False)
        self.async_write_ha_state()
