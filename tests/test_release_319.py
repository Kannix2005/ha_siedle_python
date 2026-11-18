"""Regression tests for the 3.1.9 fixes (#25, #26, #31, #32, #33)."""
import asyncio
import importlib
import sys
import types
import unittest
from unittest import mock

from test_sip_forwarding import sm, FakeSocket, hdr
import test_api_errors  # stubs requests / requests_oauthlib
from test_api_errors import api
from test_incoming_bye import INVITE


def siedle_manager():
    cfg = sm.SipConfig(host="sus2-sip.siedle.com", port=5061, username="100054631AP0002",
                       password="p", transport=sm.SipTransport.TLS)
    mgr = sm.SipCallManager(siedle_config=cfg, external_config=None)
    conn = sm.SipConnection(cfg, "Siedle-SIP")
    conn._socket = FakeSocket()
    conn._local_ip, conn._local_port, conn._registered = "10.10.10.3", 38632, True
    mgr._siedle_conn = conn
    mgr.rtp_bridge = mock.MagicMock()
    return mgr, conn._socket


def request(method, call_id="door-1", to_tag=None, cseq=1):
    to = "<sip:100054631AP0002@sus2-sip.siedle.com>" + (f";tag={to_tag}" if to_tag else "")
    return sm.SipConnection.parse_message("\r\n".join([
        f"{method} sip:100054631AP0002@10.10.10.3:38632;transport=tls SIP/2.0",
        "Via: SIP/2.0/TLS 4.184.239.221:5061;branch=z9hG4bKx1",
        'From: "100054631TA0001" <sip:1887@10.100.31.70>;tag=abc',
        f"To: {to}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        "Content-Length: 0", "", "",
    ]).encode())


class HangupWhileRingingTest(unittest.TestCase):
    """#25: a ringing doorbell call must be ended at the Siedle server."""

    def setUp(self):
        self.mgr, self.sock = siedle_manager()
        self.mgr._siedle_call = sm.SipCall(
            call_id="door-1", from_uri="a", to_uri="b", from_tag="abc",
            state=sm.CallState.RINGING_IN, invite_data=INVITE.encode())
        self.mgr._state = sm.CallState.RINGING_IN

    def test_hangup_answers_and_sends_bye_after_ack(self):
        with mock.patch.object(sm.threading, "Timer") as timer:
            self.assertTrue(self.mgr.hangup())
        timer.assert_called_once()
        self.assertEqual(len(self.sock.sent), 1)
        ok = self.sock.sent[0]
        self.assertTrue(ok.startswith("SIP/2.0 200 OK"))
        self.assertEqual(hdr(ok, "CSeq"), "4711 INVITE")
        self.assertIn("a=inactive", ok)
        self.mgr.rtp_bridge.setup.assert_not_called()

        self.mgr._handle_siedle_message(request("ACK", to_tag="x"))
        self.assertEqual(len(self.sock.sent), 2)
        self.assertTrue(self.sock.sent[1].startswith("BYE sip:asterisk@10.100.31.70:5060 SIP/2.0"))
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)

    def test_bye_goes_out_without_ack_and_only_once(self):
        with mock.patch.object(sm.threading, "Timer"):
            self.mgr.hangup()
        self.mgr._finish_answer_hangup()  # what the fallback timer runs
        self.mgr._finish_answer_hangup()
        self.assertEqual([m.split()[0] for m in self.sock.sent], ["SIP/2.0", "BYE"])

    def test_cancel_after_the_answer_gets_no_487(self):
        with mock.patch.object(sm.threading, "Timer"):
            self.mgr.hangup()
        self.mgr._handle_siedle_message(request("CANCEL", cseq=4711))
        self.assertFalse(any(m.startswith("SIP/2.0 487") for m in self.sock.sent))

    def test_error_responses_carry_a_to_tag(self):
        invite = sm.SipConnection.parse_message(INVITE.encode())
        resp = self.mgr._siedle_conn.create_response(invite, 487, "Request Terminated").decode()
        self.assertIn(";tag=", hdr(resp, "To"))
        trying = self.mgr._siedle_conn.create_response(invite, 100, "Trying").decode()
        self.assertNotIn(";tag=", hdr(trying, "To"))


class OtherRequestsTest(unittest.TestCase):
    """#33: requests outside the call logic must not stay unanswered."""

    def setUp(self):
        self.mgr, self.sock = siedle_manager()

    def test_options_and_update_get_200(self):
        for method in ("OPTIONS", "UPDATE", "NOTIFY"):
            self.mgr._handle_siedle_message(request(method))
            self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 200 OK"), method)
            self.assertEqual(hdr(self.sock.sent[-1], "CSeq"), f"1 {method}")

    def test_pings_do_not_push_out_the_tag_of_a_running_call(self):
        conn = self.mgr._siedle_conn
        invite = sm.SipConnection.parse_message(INVITE.encode())
        conn.create_response(invite, 200, "OK")
        tag = conn._dialog_to_tags["door-1"]
        for i in range(300):
            self.mgr._handle_siedle_message(request("OPTIONS", call_id=f"ping-{i}"))
        self.assertIn(f";tag={tag}", hdr(conn.create_bye_for_incoming(invite).decode(), "From"))

    def test_unknown_request_gets_501(self):
        self.mgr._handle_siedle_message(request("PUBLISH"))
        self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 501"))

    def test_reinvite_is_answered_with_our_sdp_and_keeps_the_call(self):
        call = sm.SipCall(call_id="door-1", from_uri="a", to_uri="b", from_tag="abc",
                          state=sm.CallState.CONNECTED, invite_data=INVITE.encode())
        call.local_sdp = "v=0\r\nm=audio 4000 RTP/SAVP 8\r\n"
        self.mgr._siedle_call = call
        self.mgr._state = sm.CallState.CONNECTED
        doorbell = mock.MagicMock()
        self.mgr.set_on_doorbell(doorbell)
        self.mgr._handle_siedle_message(request("INVITE", to_tag="ours", cseq=2))
        self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 200 OK"))
        self.assertIn("m=audio 4000", self.sock.sent[-1])
        self.assertIs(self.mgr._siedle_call, call)
        doorbell.assert_not_called()

    def test_reinvite_for_unknown_call_gets_481(self):
        self.mgr._handle_siedle_message(request("INVITE", call_id="gone", to_tag="ours"))
        self.assertTrue(self.sock.sent[-1].startswith("SIP/2.0 481"))


class ReRegisterTest(unittest.TestCase):
    """#26: every refresh starts without credentials and answers one challenge."""

    def setUp(self):
        cfg = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer", password="pw")
        self.conn = sm.SipConnection(cfg, "External-SIP")
        self.sock = FakeSocket()
        self.conn._socket = self.sock
        self.conn._connected = self.conn._registered = True
        self.conn._local_ip, self.conn._local_port = "192.168.178.26", 40000
        self.conn._realm, self.conn._nonce = "fritz.box", "OLD"

    def challenge(self, nonce):
        return sm.SipConnection.parse_message((
            "SIP/2.0 401 Unauthorized\r\nCall-ID: r\r\nCSeq: 5 REGISTER\r\n"
            f'WWW-Authenticate: Digest realm="fritz.box", nonce="{nonce}"\r\n'
            "Content-Length: 0\r\n\r\n").encode())

    def test_refresh_does_not_reuse_the_old_nonce(self):
        self.conn._send_re_register()
        self.assertNotIn("Authorization:", self.sock.sent[0])
        self.conn._handle_register_auth_challenge(self.challenge("NEW"))
        self.assertIn('nonce="NEW"', hdr(self.sock.sent[1], "Authorization"))
        self.assertFalse(self.conn._connection_lost)

    def test_second_challenge_marks_the_connection_as_lost(self):
        self.conn._send_re_register()
        self.conn._handle_register_auth_challenge(self.challenge("N1"))
        self.conn._handle_register_auth_challenge(self.challenge("N2"))
        self.assertEqual(len(self.sock.sent), 2)  # no endless retries
        self.assertTrue(self.conn._connection_lost)
        self.assertFalse(self.conn._registered)

    def test_refresh_interval_follows_the_granted_expires(self):
        ok = sm.SipConnection.parse_message((
            "SIP/2.0 200 OK\r\nCall-ID: r\r\nCSeq: 6 REGISTER\r\n"
            "Contact: <sip:tuer@192.168.178.26:40000>;expires=120\r\n"
            "Content-Length: 0\r\n\r\n").encode())
        self.conn._apply_granted_expires(ok)
        self.assertEqual(self.conn.re_register_interval, 60)

    def test_shortest_listed_binding_sets_the_interval(self):
        ok = sm.SipConnection.parse_message((
            "SIP/2.0 200 OK\r\nCall-ID: r\r\nCSeq: 6 REGISTER\r\n"
            "Contact: <sip:app@1.2.3.4>;expires=3600, <sip:tuer@192.168.178.26:40000>;expires=200\r\n"
            "Content-Length: 0\r\n\r\n").encode())
        self.conn._apply_granted_expires(ok)
        self.assertEqual(self.conn.re_register_interval, 100)


class TokenRefreshTest(unittest.TestCase):
    """#33: a 401 must make the next request refresh the access token."""

    def test_force_expire_marks_the_token_as_expired(self):
        s = api.Siedle.__new__(api.Siedle)
        s._token_lock = api.threading.Lock()
        s.auth_invalid = False
        s._last_refresh = 0
        s._client_id, s._extra, s._tokenSaver = "id", {}, None
        s._token = {"access_token": "a", "expires_at": api.time.time() + 3600}
        with mock.patch.object(api, "OAuth2Session") as session:
            s.refreshToken(force_expire=True)
        self.assertLess(session.call_args.kwargs["token"]["expires_at"], api.time.time())


class DoorCallPermissionTest(unittest.TestCase):
    """#29: Siedle decides per installation whether the door may be called."""

    def allowed(self, config):
        s = api.Siedle.__new__(api.Siedle)
        s._config = config
        return s.door_direct_call_allowed()

    def test_follows_the_endpoint_config(self):
        self.assertFalse(self.allowed({"allowDoorDirectCall": False, "sip": {}}))
        self.assertTrue(self.allowed({"allowDoorDirectCall": False, "doorDirectCall": {}}))
        self.assertTrue(self.allowed({"allowDoorDirectCall": True}))

    def test_missing_config_is_not_reported_as_forbidden(self):
        s = api.Siedle.__new__(api.Siedle)
        s._config = None
        s._load_config = lambda: None
        self.assertTrue(s.door_direct_call_allowed())


class MqttFirstConnectTest(unittest.TestCase):
    """#31: a failed first connection must keep being retried by paho."""

    def test_client_keeps_its_loop_when_the_broker_is_unreachable(self):
        s = api.Siedle.__new__(api.Siedle)
        s._mqtt_client, s._mqtt_connected, s._mqtt_callbacks = None, False, []
        s.get_mqtt_credentials = lambda: {
            "host": "h", "port": 8883, "clientId": "c", "username": "u",
            "password": "p", "protocol": "tcp"}
        client = mock.MagicMock()
        clock = iter(range(0, 10000, 5))
        with mock.patch.object(api, "mqtt", mock.MagicMock(Client=lambda **kw: client)), \
             mock.patch.object(api.time, "time", lambda: next(clock)), \
             mock.patch.object(api.time, "sleep"):
            self.assertFalse(s.connect_mqtt())
        client.connect_async.assert_called_once()
        client.loop_start.assert_called_once()
        client.loop_stop.assert_not_called()


def _stub_homeassistant():
    def redact(data, keys):
        return {k: ("**REDACTED**" if k in keys else v) for k, v in data.items()}
    mods = {
        "homeassistant": {},
        "homeassistant.config_entries": {"ConfigEntry": object},
        "homeassistant.core": {"HomeAssistant": object, "callback": lambda f: f},
        "homeassistant.helpers": {},
        "homeassistant.helpers.redact": {"async_redact_data": redact},
        "homeassistant.helpers.dispatcher": {"async_dispatcher_send": mock.MagicMock()},
        "homeassistant.helpers.event": {"async_call_later": mock.MagicMock()},
    }
    for name, attrs in mods.items():
        mod = sys.modules.setdefault(name, types.ModuleType(name))
        for key, value in attrs.items():
            if not hasattr(mod, key):
                setattr(mod, key, value)


class DiagnosticsRedactionTest(unittest.TestCase):
    """#32: the DTMF door code must not appear in a diagnostics download."""

    def test_dtmf_codes_and_caller_ids_are_redacted(self):
        _stub_homeassistant()
        diag = importlib.import_module("siedle_ut.diagnostics")
        self.assertLessEqual({"dtmf_door_code", "dtmf_light_code"}, diag.TO_REDACT_OPTIONS)
        self.assertEqual(diag.TO_REDACT_HISTORY, {"from", "caller_id"})


class FcmShutdownTest(unittest.TestCase):
    """#33: no FCM listener may start once the entry is unloaded."""

    def test_start_after_shutdown_does_nothing(self):
        _stub_homeassistant()
        fcm = importlib.import_module("siedle_ut.fcm_handler")
        handler = fcm.SiedleFCMHandler.__new__(fcm.SiedleFCMHandler)
        handler._closed = handler._running = False
        handler._hass = mock.MagicMock()

        async def stop():
            pass
        handler.async_stop = stop
        asyncio.run(handler.async_shutdown())
        self.assertFalse(asyncio.run(handler.async_start()))
        handler._hass.async_add_executor_job.assert_not_called()


if __name__ == "__main__":
    unittest.main()
