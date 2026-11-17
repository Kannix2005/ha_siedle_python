"""Regression tests for external call forwarding (issue #23).

Run:  python3 -m unittest discover -s <this dir> -v   (REPO env var = repo root)
"""
import importlib
import os
import re
import sys
import types
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pkg = types.ModuleType("siedle_ut")
pkg.__path__ = [os.path.join(REPO, "custom_components", "siedle")]
sys.modules.setdefault("siedle_ut", pkg)
sm = importlib.import_module("siedle_ut.sip_manager")
rh = importlib.import_module("siedle_ut.rtp_handler")


class FakeSocket:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data.decode())


def hdr(msg: str, name: str) -> str:
    m = re.search(rf"^{name}:\s*(.*?)\r?$", msg, re.M)
    return m.group(1) if m else ""


def branch(msg: str) -> str:
    return re.search(r"branch=([^;\s]+)", hdr(msg, "Via")).group(1)


def response(request: str, code: int, text: str, extra=(), body="", to_tag="srv1", cseq=None):
    to = hdr(request, "To")
    if to_tag:
        to += f";tag={to_tag}"
    lines = [
        f"SIP/2.0 {code} {text}",
        f"Via: {hdr(request, 'Via')};received=192.168.178.26",
        f"From: {hdr(request, 'From')}",
        f"To: {to}",
        f"Call-ID: {hdr(request, 'Call-ID')}",
        f"CSeq: {cseq or hdr(request, 'CSeq')}",
        *extra,
        f"Content-Length: {len(body)}",
        "",
        body,
    ]
    return sm.SipConnection.parse_message("\r\n".join(lines).encode())


SDP = "v=0\r\nc=IN IP4 192.168.178.1\r\nm=audio 7078 RTP/AVP 8 101\r\n"
CHALLENGE = ('WWW-Authenticate: Digest realm="fritz.box", nonce="ABCDEF"',)


class ForwardingTest(unittest.TestCase):
    def setUp(self):
        ext = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer", password="pw")
        self.mgr = sm.SipCallManager(
            siedle_config=sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p"),
            external_config=ext, forward_to_number="11", forward_timeout=0,
            dtmf_enabled=True,
        )
        conn = sm.SipConnection(ext, "External-SIP")
        self.sock = FakeSocket()
        conn._socket = self.sock
        conn._local_ip = "192.168.178.26"
        conn._local_port = 40000
        conn._registered = True
        self.mgr._external_conn = conn
        self.mgr.rtp_bridge = mock.MagicMock()
        self.mgr.rtp_bridge.local_port_b = 36584
        self.mgr._siedle_call = sm.SipCall(
            call_id="siedle-1", from_uri="a", to_uri="b", from_tag="t",
            state=sm.CallState.RINGING_IN)
        self.mgr._state = sm.CallState.RINGING_IN
        self.bridge = mock.MagicMock()
        self.mgr._answer_siedle_and_bridge = self.bridge
        self.mgr._forward_to_external_target("11")

    @property
    def sent(self):
        return self.sock.sent

    def feed(self, msg):
        self.mgr._handle_external_message(msg)

    def authenticate(self):
        """INVITE -> 401 -> ACK + INVITE with credentials. Returns (invite1, ack, invite2)."""
        invite1 = self.sent[0]
        self.feed(response(invite1, 401, "Unauthorized", CHALLENGE))
        self.assertEqual(len(self.sent), 3)
        return invite1, self.sent[1], self.sent[2]

    def test_ack_for_401_belongs_to_invite_transaction(self):
        invite1, ack, _ = self.authenticate()
        self.assertTrue(ack.startswith("ACK sip:11@192.168.178.1 SIP/2.0"))
        self.assertEqual(branch(ack), branch(invite1))
        self.assertEqual(hdr(ack, "CSeq"), "1 ACK")
        self.assertIn("tag=srv1", hdr(ack, "To"))

    def test_auth_retry_continues_same_dialog(self):
        invite1, _, invite2 = self.authenticate()
        self.assertTrue(invite2.startswith("INVITE "))
        self.assertEqual(hdr(invite2, "Call-ID"), hdr(invite1, "Call-ID"))
        self.assertEqual(hdr(invite2, "From"), hdr(invite1, "From"))
        self.assertEqual(hdr(invite2, "CSeq"), "2 INVITE")
        self.assertNotEqual(branch(invite2), branch(invite1))
        self.assertIn('Digest username="tuer"', hdr(invite2, "Authorization"))
        self.assertIn("m=audio", invite2)

    def test_stale_481_does_not_kill_the_call(self):
        invite1, _, invite2 = self.authenticate()
        # FRITZ!Box answers the first transaction / the ACK with a 481
        self.feed(response(invite1, 481, "Call Leg/Transaction Does Not Exist"))
        self.feed(response(invite1, 481, "Call Leg/Transaction Does Not Exist", cseq="1 ACK"))
        self.assertIsNotNone(self.mgr._external_call)
        self.assertEqual(self.mgr.state, sm.CallState.RINGING_OUT)
        self.feed(response(invite2, 183, "Session Progress"))
        n = len(self.sent)
        self.feed(response(invite2, 200, "OK", ("Content-Type: application/sdp",), SDP))
        self.bridge.assert_called_once()
        ack = self.sent[n]
        self.assertTrue(ack.startswith("ACK "))
        self.assertEqual(hdr(ack, "CSeq"), "2 ACK")
        self.assertNotEqual(branch(ack), branch(invite2))
        self.assertEqual(self.mgr._external_call.remote_rtp_port, 7078)

    def test_retransmitted_200_is_acked_but_not_bridged_twice(self):
        _, _, invite2 = self.authenticate()
        ok = response(invite2, 200, "OK", ("Content-Type: application/sdp",), SDP)
        self.feed(ok)
        n = len(self.sent)
        self.feed(ok)
        self.bridge.assert_called_once()
        self.assertEqual(len(self.sent), n + 1)
        self.assertTrue(self.sent[n].startswith("ACK "))

    def test_rejection_is_acked_once_handled_and_retransmits_ignored(self):
        _, _, invite2 = self.authenticate()
        busy = response(invite2, 486, "Busy Here")
        n = len(self.sent)
        self.feed(busy)
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)
        ack = self.sent[n]
        self.assertTrue(ack.startswith("ACK "))
        self.assertEqual(branch(ack), branch(invite2))
        self.assertEqual(hdr(ack, "CSeq"), "2 ACK")
        self.assertEqual(len(self.sent), n + 1)  # no CANCEL after a final response
        # Retransmitted 486 hits the *next* call: must only be ACKed
        self.mgr._siedle_call = sm.SipCall(
            call_id="siedle-2", from_uri="a", to_uri="b", from_tag="t",
            state=sm.CallState.RINGING_IN)
        self.mgr._forward_to_external_target("11")
        n = len(self.sent)
        self.feed(busy)
        self.assertEqual(self.mgr.state, sm.CallState.RINGING_OUT)
        self.assertIsNotNone(self.mgr._external_call)
        self.assertEqual(len(self.sent), n + 1)
        self.assertTrue(self.sent[n].startswith("ACK "))

    def test_second_401_gives_up_instead_of_looping(self):
        _, _, invite2 = self.authenticate()
        n = len(self.sent)
        self.feed(response(invite2, 401, "Unauthorized", CHALLENGE))
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)
        self.assertEqual([m.split()[0] for m in self.sent[n:]], ["ACK"])

    def test_cancel_matches_the_pending_invite(self):
        _, _, invite2 = self.authenticate()
        n = len(self.sent)
        self.mgr._end_call()
        cancel = self.sent[n]
        self.assertTrue(cancel.startswith("CANCEL sip:11@192.168.178.1 SIP/2.0"))
        self.assertEqual(hdr(cancel, "Via"), hdr(invite2, "Via"))
        self.assertEqual(hdr(cancel, "From"), hdr(invite2, "From"))
        self.assertEqual(hdr(cancel, "To"), hdr(invite2, "To"))
        self.assertEqual(hdr(cancel, "Call-ID"), hdr(invite2, "Call-ID"))
        self.assertEqual(hdr(cancel, "CSeq"), "2 CANCEL")
        # 200 (CANCEL) and 487 (INVITE) follow: only the 487 is ACKed
        n = len(self.sent)
        self.feed(response(cancel, 200, "OK"))
        self.feed(response(invite2, 487, "Request Terminated"))
        self.assertEqual([m.split()[0] for m in self.sent[n:]], ["ACK"])
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)
        self.bridge.assert_not_called()

    def test_late_200_for_abandoned_call_is_acked_and_hung_up(self):
        _, _, invite2 = self.authenticate()
        self.mgr._end_call()
        n = len(self.sent)
        self.feed(response(invite2, 200, "OK", ("Content-Type: application/sdp",), SDP))
        self.bridge.assert_not_called()
        self.assertEqual([m.split()[0] for m in self.sent[n:]], ["ACK", "BYE"])
        bye = self.sent[n + 1]
        self.assertEqual(hdr(bye, "CSeq"), "3 BYE")
        self.assertEqual(hdr(bye, "Call-ID"), hdr(invite2, "Call-ID"))
        self.assertIn("tag=srv1", hdr(bye, "To"))
        self.assertEqual(hdr(bye, "From"), hdr(invite2, "From"))

    def test_bye_cseq_is_higher_than_invite(self):
        _, _, invite2 = self.authenticate()
        self.feed(response(invite2, 200, "OK", ("Content-Type: application/sdp",), SDP))
        n = len(self.sent)
        self.mgr._end_call()
        self.assertEqual(hdr(self.sent[n], "CSeq"), "3 BYE")

    def _fire_timeout(self):
        self.mgr.forward_timeout = 30
        with mock.patch.object(sm.threading, "Timer") as timer:
            self.mgr._start_forward_timeout()
        timer.call_args[0][1]()

    def test_timeout_moves_on_to_next_target(self):
        self.mgr.forward_to_number = "11,12"
        invite_a = self.sent[0]
        n = len(self.sent)
        with mock.patch.object(sm.threading, "Timer"):
            self._fire_timeout()
        cancel, invite_b = self.sent[n], self.sent[n + 1]
        self.assertEqual(hdr(cancel, "Via"), hdr(invite_a, "Via"))
        self.assertTrue(invite_b.startswith("INVITE sip:12@"))
        n = len(self.sent)
        self.feed(response(invite_a, 487, "Request Terminated"))
        self.assertEqual([m.split()[0] for m in self.sent[n:]], ["ACK"])
        self.assertEqual(self.mgr._external_call.to_uri, "sip:12@192.168.178.1")
        self.assertEqual(self.mgr.state, sm.CallState.RINGING_OUT)

    def test_timeout_fallback_cancels_before_answering_locally(self):
        self.mgr.auto_answer = True
        self.mgr._answer_siedle_call = mock.MagicMock()
        invite = self.sent[0]
        n = len(self.sent)
        self._fire_timeout()
        self.assertTrue(self.sent[n].startswith("CANCEL "))
        self.mgr._answer_siedle_call.assert_called_once()
        self.feed(response(invite, 487, "Request Terminated"))
        self.feed(response(invite, 200, "OK", ("Content-Type: application/sdp",), SDP))
        self.mgr._answer_siedle_call.assert_called_once()
        self.bridge.assert_not_called()
        self.assertEqual([m.split()[0] for m in self.sent[n + 1:]], ["ACK", "ACK", "BYE"])

    def _info(self, body, ctype, cseq=10):
        call = self.mgr._external_call
        lines = [
            "INFO sip:tuer@192.168.178.26:40000 SIP/2.0",
            "Via: SIP/2.0/UDP 192.168.178.1:5060;branch=z9hG4bKinfo%d" % cseq,
            "From: <sip:11@192.168.178.1>;tag=srv1",
            f"To: <sip:tuer@192.168.178.1>;tag={call.from_tag}",
            f"Call-ID: {call.call_id}",
            f"CSeq: {cseq} INFO",
            f"Content-Type: {ctype}",
            f"Content-Length: {len(body)}",
            "",
            body,
        ]
        return sm.SipConnection.parse_message("\r\n".join(lines).encode())

    def test_sip_info_dtmf_is_answered_and_forwarded(self):
        _, _, invite2 = self.authenticate()
        self.feed(response(invite2, 200, "OK", ("Content-Type: application/sdp",), SDP))
        inject = self.mgr.rtp_bridge.inject_dtmf_digit
        n = len(self.sent)
        info = self._info("Signal=#\r\nDuration=160\r\n", "application/dtmf-relay")
        self.feed(info)
        self.feed(info)  # retransmission
        self.assertTrue(all(m.startswith("SIP/2.0 200 OK") for m in self.sent[n:]))
        self.assertEqual(len(self.sent), n + 2)
        self.assertEqual(hdr(self.sent[n], "CSeq"), "10 INFO")
        inject.assert_called_once_with("#")
        self.feed(self._info("5", "application/dtmf", cseq=11))
        self.assertEqual(inject.call_args_list[-1], mock.call("5"))


class DtmfDetectorTest(unittest.TestCase):
    def test_digit_from_info_reaches_callbacks(self):
        digits = []
        det = rh.DtmfDetector(on_digit=digits.append, code_timeout=60)
        self.addCleanup(det.reset)
        det.process_digit("#")
        self.assertEqual(digits, ["#"])

    def test_same_digit_via_rtp_and_info_counts_once(self):
        digits = []
        det = rh.DtmfDetector(on_digit=digits.append, code_timeout=60)
        self.addCleanup(det.reset)
        pkt = mock.MagicMock(payload_type=101, payload=bytes([11, 0x80, 0, 160]))
        det.process_rtp(pkt)
        det.process_digit("#")
        self.assertEqual(digits, ["#"])
        det._last_digit_time -= 2  # a later, second key press counts again
        det.process_digit("#")
        self.assertEqual(digits, ["#", "#"])


if __name__ == "__main__":
    unittest.main()
