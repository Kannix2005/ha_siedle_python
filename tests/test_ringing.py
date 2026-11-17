"""180 Ringing for a doorbell INVITE.

The Siedle app (pjsua) answers every incoming call with 180 right away and
only later with 200. Without the 180 the Siedle server connected the call but
sent digital silence instead of the door audio.
"""
import unittest

from test_sip_forwarding import sm, FakeSocket, hdr
from test_incoming_bye import INVITE


class RingingResponseTest(unittest.TestCase):
    def setUp(self):
        cfg = sm.SipConfig(host="sus2-sip.siedle.com", port=5061, username="100054631AP0002",
                           password="p", transport=sm.SipTransport.TLS)
        self.conn = sm.SipConnection(cfg, "Siedle-SIP")
        self.conn._socket = FakeSocket()
        self.conn._local_ip, self.conn._local_port = "10.10.10.3", 38632
        self.invite = sm.SipConnection.parse_message(INVITE.encode())
        self.ringing = self.conn.create_response(self.invite, 180, "Ringing").decode()

    def test_ringing_carries_the_dialog_tag_of_the_later_ok(self):
        ok = self.conn.create_response(self.invite, 200, "OK").decode()
        self.assertIn(";tag=", hdr(self.ringing, "To"))
        self.assertEqual(hdr(self.ringing, "To"), hdr(ok, "To"))

    def test_ringing_establishes_the_early_dialog(self):
        routes = [l[14:] for l in self.ringing.split("\r\n") if l.startswith("Record-Route: ")]
        self.assertEqual(routes, self.invite.record_route_list)
        self.assertTrue(hdr(self.ringing, "Contact"))

    def test_trying_stays_without_tag(self):
        trying = self.conn.create_response(self.invite, 100, "Trying").decode()
        self.assertNotIn(";tag=", hdr(trying, "To"))


if __name__ == "__main__":
    unittest.main()
