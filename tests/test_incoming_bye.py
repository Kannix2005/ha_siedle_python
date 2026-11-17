"""BYE for a call the door station placed (we are the callee)."""
import unittest

from test_sip_forwarding import sm, FakeSocket, hdr

INVITE = "\r\n".join([
    "INVITE sip:100054631AP0002@84.118.44.50:16664;transport=tls SIP/2.0",
    "Record-Route: <sip:4.184.239.221:5061;transport=tls;r2=on;lr=on;ftag=abc>",
    "Record-Route: <sip:4.184.239.221;r2=on;lr=on;ftag=abc>",
    "Via: SIP/2.0/TLS 4.184.239.221:5061;branch=z9hG4bKee6f.0",
    "Via: SIP/2.0/UDP 10.100.31.70:5060;rport=5060;branch=z9hG4bKPj1",
    'From: "100054631TA0001" <sip:1887@10.100.31.70>;tag=abc',
    "To: <sip:100054631AP0002@sus2-sip.siedle.com>",
    "Contact: <sip:asterisk@10.100.31.70:5060>",
    "Call-ID: door-1",
    "CSeq: 4711 INVITE",
    "Content-Length: 0", "", "",
])


class IncomingByeTest(unittest.TestCase):
    def setUp(self):
        cfg = sm.SipConfig(host="sus2-sip.siedle.com", port=5061, username="100054631AP0002",
                           password="p", transport=sm.SipTransport.TLS)
        self.conn = sm.SipConnection(cfg, "Siedle-SIP")
        self.conn._socket = FakeSocket()
        self.conn._local_ip, self.conn._local_port = "10.10.10.3", 38632
        self.invite = sm.SipConnection.parse_message(INVITE.encode())
        self.ok = self.conn.create_response(self.invite, 200, "OK").decode()
        self.bye = self.conn.create_bye_for_incoming(self.invite).decode()

    def test_request_line_targets_the_callers_contact(self):
        self.assertTrue(self.bye.startswith("BYE sip:asterisk@10.100.31.70:5060 SIP/2.0\r\n"))

    def test_from_and_to_are_the_dialog_parties_swapped(self):
        # We answered as "To" of the INVITE, so in our own request we are "From"
        self.assertEqual(hdr(self.bye, "From"), hdr(self.ok, "To"))
        self.assertIn(";tag=", hdr(self.bye, "From"))
        self.assertEqual(hdr(self.bye, "To"), '"100054631TA0001" <sip:1887@10.100.31.70>;tag=abc')
        self.assertEqual(hdr(self.bye, "Call-ID"), "door-1")

    def test_route_set_follows_record_route(self):
        routes = [l[7:] for l in self.bye.split("\r\n") if l.startswith("Route: ")]
        self.assertEqual(routes, self.invite.record_route_list)


if __name__ == "__main__":
    unittest.main()
