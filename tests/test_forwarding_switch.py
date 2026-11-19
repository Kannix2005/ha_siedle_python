"""The forwarding switch turns forwarding on and off without reloading the integration."""
import asyncio
import importlib
import sys
import types
import unittest

from test_sip_forwarding import sm


def _stub(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules.setdefault(name, module)


class _Entity:
    hass = None

    async def async_added_to_hass(self):
        pass

    def async_write_ha_state(self):
        self.written = True


class _SwitchEntity(_Entity):
    pass


class _RestoreEntity(_Entity):
    last_state = None

    async def async_get_last_state(self):
        return self.last_state


class HomeAssistantError(Exception):
    pass


for _name in ("homeassistant", "homeassistant.components", "homeassistant.helpers"):
    _stub(_name)
_stub("homeassistant.components.switch", SwitchEntity=_SwitchEntity)
_stub("homeassistant.config_entries", ConfigEntry=object)
_stub("homeassistant.core", HomeAssistant=object)
_stub("homeassistant.exceptions", HomeAssistantError=HomeAssistantError)
_stub("homeassistant.helpers.entity", DeviceInfo=dict)
_stub("homeassistant.helpers.entity_platform", AddEntitiesCallback=object)
_stub("homeassistant.helpers.restore_state", RestoreEntity=_RestoreEntity)

switch = importlib.import_module("siedle_ut.switch")
HomeAssistantError = sys.modules["homeassistant.exceptions"].HomeAssistantError


def manager(**kwargs):
    return sm.SipCallManager(
        siedle_config=sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p"),
        **kwargs)


class ManagerForwardingTest(unittest.TestCase):
    def test_forwarding_is_on_by_default_when_a_target_is_configured(self):
        self.assertEqual(manager(forward_to_number="11").forward_to_number, "11")

    def test_disabled_at_start_keeps_the_configured_target_for_later(self):
        mgr = manager(forward_to_number="11,12", forward_enabled=False)
        self.assertIsNone(mgr.forward_to_number)
        self.assertEqual(mgr._get_forward_targets(), [])
        mgr.set_forwarding_enabled(True)
        self.assertEqual(mgr._get_forward_targets(), ["11", "12"])
        mgr.set_forwarding_enabled(False)
        self.assertIsNone(mgr.forward_to_number)

    def test_enabling_without_a_target_forwards_nothing(self):
        mgr = manager(forward_to_number="")
        mgr.set_forwarding_enabled(True)
        self.assertIsNone(mgr.forward_to_number)

    def test_caller_filter_does_not_depend_on_the_switch(self):
        mgr = manager(forward_to_number="11", forward_from_number="610", forward_enabled=False)
        self.assertEqual(mgr.forward_from_number, "610")
        mgr.set_forwarding_enabled(True)
        mgr.set_forwarding_enabled(False)
        self.assertEqual(mgr.forward_from_number, "610")


class FakeHass:
    async def async_add_executor_job(self, func, *args):
        return func(*args)


def entity(mgr, last_state=None):
    entry = types.SimpleNamespace(entry_id="e1", data={"endpoint_id": "9e2ba7e8-xyz"})
    ent = switch.SiedleForwardingSwitch(entry, mgr)
    ent.hass = FakeHass()
    if last_state is not None:
        ent.last_state = types.SimpleNamespace(state=last_state)
    asyncio.run(ent.async_added_to_hass())
    return ent


class ForwardingSwitchTest(unittest.TestCase):
    def test_without_a_stored_state_the_option_is_the_start_value(self):
        self.assertFalse(entity(manager(forward_to_number="11", forward_enabled=False)).is_on)
        self.assertTrue(entity(manager(forward_to_number="11")).is_on)

    def test_stored_state_wins_over_the_option(self):
        mgr = manager(forward_to_number="11", forward_enabled=False)
        self.assertTrue(entity(mgr, last_state="on").is_on)
        self.assertEqual(mgr.forward_to_number, "11")

        mgr = manager(forward_to_number="11")
        self.assertFalse(entity(mgr, last_state="off").is_on)
        self.assertIsNone(mgr.forward_to_number)

    def test_unusable_stored_state_is_ignored(self):
        self.assertTrue(entity(manager(forward_to_number="11"), last_state="unavailable").is_on)

    def test_turning_on_and_off_changes_the_manager_and_reports_the_state(self):
        mgr = manager(forward_to_number="11", forward_enabled=False)
        ent = entity(mgr)
        asyncio.run(ent.async_turn_on())
        self.assertEqual(mgr.forward_to_number, "11")
        self.assertTrue(ent.is_on and ent.written)
        asyncio.run(ent.async_turn_off())
        self.assertIsNone(mgr.forward_to_number)
        self.assertFalse(ent.is_on)

    def test_without_a_target_the_switch_is_unavailable_and_refuses(self):
        ent = entity(manager(forward_to_number=None), last_state="on")
        self.assertFalse(ent.available)
        self.assertFalse(ent.is_on)
        with self.assertRaises(HomeAssistantError):
            asyncio.run(ent.async_turn_on())

    def test_setup_adds_no_switch_without_sip(self):
        added = []
        hass = types.SimpleNamespace(data={switch.DOMAIN: {"e1": {"sip_manager": None}}})
        entry = types.SimpleNamespace(entry_id="e1", data={})
        asyncio.run(switch.async_setup_entry(hass, entry, added.extend))
        self.assertEqual(added, [])


if __name__ == "__main__":
    unittest.main()
