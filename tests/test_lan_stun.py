"""A SIP server on the LAN must not get the STUN public address (#21)."""
import unittest
from unittest import mock

import importlib

from test_sip_forwarding import sm

stun = importlib.import_module(sm.__package__ + ".stun_client")


class LanStunTest(unittest.TestCase):
    def _conn(self, host):
        cfg = sm.SipConfig(host=host, port=5060, username="u", password="p")
        conn = sm.SipConnection(cfg, "External-SIP")
        conn._local_ip, conn._local_port = "192.168.10.242", 5060
        return conn

    def test_lan_server_skips_stun(self):
        conn = self._conn("192.168.10.1")
        with mock.patch.object(stun, "discover_external_address",
                               side_effect=AssertionError("STUN must not run")):
            conn._discover_external_ip_via_stun()
        self.assertIsNone(conn._external_ip)
        self.assertEqual(conn.get_sdp_ip(), "192.168.10.242")

    def test_lan_server_behind_nat_keeps_received(self):
        conn = self._conn("192.168.10.1")
        conn._extract_via_received(mock.Mock(via="SIP/2.0/UDP 192.168.20.5:5060;received=192.168.10.50;rport=40000"))
        conn._discover_external_ip_via_stun()
        self.assertEqual(conn.get_sdp_ip(), "192.168.10.50")

    def test_public_server_still_uses_stun(self):
        conn = self._conn("8.8.8.8")
        with mock.patch.object(stun, "discover_external_address", return_value=("1.2.3.4", 999)):
            conn._discover_external_ip_via_stun()
        self.assertEqual(conn.get_sdp_ip(), "1.2.3.4")

    def test_missing_external_address_is_only_a_warning_for_a_public_server(self):
        with self.assertNoLogs(sm._LOGGER, level="WARNING"):
            self._conn("192.168.10.1")._log_sdp_address()
        with self.assertLogs(sm._LOGGER, level="WARNING"):
            self._conn("8.8.8.8")._log_sdp_address()


if __name__ == "__main__":
    unittest.main()
