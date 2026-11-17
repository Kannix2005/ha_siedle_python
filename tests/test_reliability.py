"""Regression tests for the 3.1.6 reliability fixes."""
import time
import unittest
from unittest import mock

from test_sip_forwarding import sm, rh, FakeSocket, hdr


class ReconnectTest(unittest.TestCase):
    def setUp(self):
        cfg = sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p")
        self.mgr = sm.SipCallManager(siedle_config=cfg, external_config=cfg)

    def test_failed_reconnect_stays_marked_as_lost(self):
        with mock.patch.object(sm.SipConnection, "register", return_value=False):
            self.assertFalse(self.mgr._reconnect_siedle())
            self.assertFalse(self.mgr._reconnect_external())
        # The health monitor only retries connections that report as lost
        self.assertTrue(self.mgr._siedle_conn.connection_lost)
        self.assertTrue(self.mgr._external_conn.connection_lost)

    def test_external_register_failure_at_start_is_retried(self):
        def register(conn):
            return conn.name == "Siedle-SIP"
        with mock.patch.object(sm.SipConnection, "register", register), \
             mock.patch.object(sm.SipConnection, "start_listen_loop"), \
             mock.patch.object(sm.threading, "Thread"):
            self.assertTrue(self.mgr.start())
        self.assertTrue(self.mgr._external_conn.connection_lost)
        self.assertFalse(self.mgr._siedle_conn.connection_lost)


class IncomingExternalInviteTest(unittest.TestCase):
    def setUp(self):
        ext = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer", password="pw")
        self.mgr = sm.SipCallManager(
            siedle_config=sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p"),
            external_config=ext, forward_to_number="11", forward_timeout=0)
        conn = sm.SipConnection(ext, "External-SIP")
        self.sock = FakeSocket()
        conn._socket = self.sock
        conn._local_ip, conn._local_port, conn._registered = "192.168.178.26", 40000, True
        self.mgr._external_conn = conn
        self.mgr.rtp_bridge = mock.MagicMock()

    def invite(self, call_id):
        lines = [
            "INVITE sip:tuer@192.168.178.26:40000 SIP/2.0",
            "Via: SIP/2.0/UDP 192.168.178.1:5060;branch=z9hG4bKin1",
            "From: <sip:**610@192.168.178.1>;tag=abc",
            "To: <sip:tuer@192.168.178.1>",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            "Content-Length: 0", "", "",
        ]
        return sm.SipConnection.parse_message("\r\n".join(lines).encode())

    def test_incoming_invite_is_declined_and_leaves_state_alone(self):
        self.mgr._handle_external_message(self.invite("in-1"))
        self.assertTrue(self.sock.sent[0].startswith("SIP/2.0 603 Decline"))
        self.assertEqual(hdr(self.sock.sent[0], "CSeq"), "1 INVITE")
        self.assertIsNone(self.mgr._external_call)
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)

    def test_incoming_invite_does_not_replace_forwarded_call(self):
        self.mgr._forward_to_external_target("11")
        call = self.mgr._external_call
        self.mgr._handle_external_message(self.invite("in-2"))
        self.assertIs(self.mgr._external_call, call)
        self.assertEqual(self.mgr.state, sm.CallState.RINGING_OUT)
        self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 603"))
        # re-INVITE inside the forwarded call: refused, call untouched
        self.mgr._handle_external_message(self.invite(call.call_id))
        self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 488"))
        self.assertIs(self.mgr._external_call, call)


class RecordingTimerTest(unittest.TestCase):
    def test_old_timer_does_not_stop_a_newer_recording(self):
        bridge = rh.RtpBridge.__new__(rh.RtpBridge)
        bridge._recorder = None
        stopped = []
        bridge._on_recording_stopped = lambda: stopped.append(1)
        timers = []

        class FakeThread:
            def __init__(self, target, daemon=None):
                timers.append(target)

            def start(self):
                pass

        with mock.patch.object(rh, "AudioRecorder") as rec, \
             mock.patch.object(rh.threading, "Thread", FakeThread), \
             mock.patch.object(rh.time, "sleep"):
            rec.side_effect = lambda path: mock.MagicMock(is_recording=True)
            bridge.start_recording("/tmp/a.wav", duration=30)
            first = bridge._recorder
            bridge.stop_recording()
            bridge.start_recording("/tmp/b.wav", duration=30)
            second = bridge._recorder
            timers[0]()  # timer of the first recording fires late
            self.assertIs(bridge._recorder, second)
            self.assertEqual(stopped, [])
            second.stop.assert_not_called()
            timers[1]()
            self.assertIsNone(bridge._recorder)
            self.assertEqual(stopped, [1])
            first.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()


class NatTowardsLanSipServerTest(unittest.TestCase):
    """HA and the FRITZ!Box can sit in different subnets with NAT in between."""

    def forward(self, seen_as=None):
        ext = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer", password="pw")
        mgr = sm.SipCallManager(
            siedle_config=sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p"),
            external_config=ext, forward_to_number="11", forward_timeout=0)
        conn = sm.SipConnection(ext, "External-SIP")
        sock = FakeSocket()
        conn._socket = sock
        conn._local_ip, conn._local_port, conn._registered = "10.10.10.3", 40000, True
        conn._external_ip = seen_as
        conn._external_port = 49944 if seen_as else None
        mgr._external_conn = conn
        mgr.rtp_bridge = mock.MagicMock()
        mgr.rtp_bridge.setup.return_value = (36809, 50762)
        mgr.rtp_bridge.stun_discover_external_port.return_value = (None, None)
        mgr._siedle_call = sm.SipCall(call_id="siedle-1", from_uri="a", to_uri="b", from_tag="t",
                                      state=sm.CallState.RINGING_IN,
                                      remote_rtp_host="4.184.239.221", remote_rtp_port=16956)
        mgr._forward_to_external()
        return sock.sent[0]

    def test_sdp_offers_the_address_the_server_sees(self):
        self.assertIn("c=IN IP4 192.168.178.52", self.forward(seen_as="192.168.178.52"))

    def test_sdp_offers_local_address_without_nat(self):
        self.assertIn("c=IN IP4 10.10.10.3", self.forward())

    def test_contact_is_the_address_the_server_sees(self):
        # In-dialog requests (BYE when the phone hangs up) go to the Contact
        self.assertEqual(hdr(self.forward(seen_as="192.168.178.52"), "Contact"),
                         "<sip:tuer@192.168.178.52:49944;transport=udp>")

    def test_contact_is_local_address_without_nat(self):
        self.assertEqual(hdr(self.forward(), "Contact"), "<sip:tuer@10.10.10.3:40000;transport=udp>")

    def test_keepalive_responses_reveal_the_address_the_server_sees(self):
        cfg = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer", password="pw")
        conn = sm.SipConnection(cfg, "External-SIP")
        conn._local_ip = "10.10.10.3"
        reply = sm.SipConnection.parse_message((
            "SIP/2.0 401 Unauthorized\r\n"
            "Via: SIP/2.0/TCP 10.10.10.3:48542;rport=48542;branch=z9hG4bK-1;received=192.168.178.52\r\n"
            "Call-ID: k1\r\nCSeq: 7 OPTIONS\r\nContent-Length: 0\r\n\r\n").encode())
        conn._running = True
        conn.recv = mock.Mock(side_effect=[reply, StopIteration])
        try:
            conn._listen_loop()
        except StopIteration:
            pass
        self.assertEqual(conn.get_sdp_ip(), "192.168.178.52")
