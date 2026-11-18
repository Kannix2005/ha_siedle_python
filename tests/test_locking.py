"""#30: call state and socket I/O are shared by several threads."""
import socket
import threading
import time
import unittest
from unittest import mock

from test_sip_forwarding import sm, FakeSocket


def stream_connection(sock):
    cfg = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer",
                       password="pw", transport=sm.SipTransport.TCP)
    conn = sm.SipConnection(cfg, "External-SIP")
    conn._socket = sock
    conn._running = True
    return conn


class SocketIoTest(unittest.TestCase):
    def test_stream_send_writes_the_whole_message(self):
        sock = mock.MagicMock()
        stream_connection(sock).send(b"x" * 5000)
        sock.sendall.assert_called_once_with(b"x" * 5000)
        sock.send.assert_not_called()

    def test_idle_read_does_not_block_a_sender(self):
        ours, peer = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(peer.close)
        conn = stream_connection(ours)
        reader = threading.Thread(target=conn.recv, kwargs={"timeout": 0.4})
        reader.start()
        time.sleep(0.05)  # the reader now waits for data
        started = time.monotonic()
        conn.send(b"OPTIONS sip:x SIP/2.0\r\n\r\n")
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertTrue(peer.recv(100).startswith(b"OPTIONS"))
        reader.join()


class CallLockTest(unittest.TestCase):
    def setUp(self):
        cfg = sm.SipConfig(host="sip.siedle", port=5061, username="s", password="p")
        self.mgr = sm.SipCallManager(siedle_config=cfg, external_config=cfg)
        self.mgr.rtp_bridge = mock.MagicMock()
        self.mgr._state = sm.CallState.CONNECTED

    def blocked_until_release(self, target):
        """True if target waits for the call lock held by another thread."""
        self.mgr._call_lock.acquire()
        worker = threading.Thread(target=target)
        worker.start()
        worker.join(0.1)
        waited = worker.is_alive()
        self.mgr._call_lock.release()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        return waited

    def test_hangup_waits_for_a_running_handler(self):
        self.assertTrue(self.blocked_until_release(self.mgr.hangup))
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)

    def test_forward_timeout_waits_for_a_running_handler(self):
        with mock.patch.object(sm.threading, "Timer") as timer:
            self.mgr._start_forward_timeout()
        self.assertTrue(self.blocked_until_release(timer.call_args[0][1]))

    def test_cancelled_timeout_that_already_fired_does_nothing(self):
        with mock.patch.object(sm.threading, "Timer") as timer:
            self.mgr._start_forward_timeout()
        fired = timer.call_args[0][1]
        self.mgr._cancel_forward_timeout()  # e.g. the phone answered meanwhile
        fired()
        self.assertEqual(self.mgr.state, sm.CallState.CONNECTED)

    def test_handlers_may_end_the_call_themselves(self):
        with self.mgr._call_lock:  # re-entrant
            self.mgr._end_call()
        self.assertEqual(self.mgr.state, sm.CallState.IDLE)


if __name__ == "__main__":
    unittest.main()
