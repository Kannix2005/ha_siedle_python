"""STUN runs while the call lock is held, so it must stay short when servers are silent."""
import importlib
import socket
import struct
import time
import unittest
from unittest import mock

import test_sip_forwarding  # registers the siedle_ut package

stun = importlib.import_module("siedle_ut.stun_client")

HOSTS = {host: f"198.51.100.{i + 1}" for i, (host, _) in enumerate(stun.STUN_SERVERS)}


def binding_response(request: bytes, ip="203.0.113.7", port=40123) -> bytes:
    attr = struct.pack(
        "!BBHI", 0, 0x01,
        port ^ (stun.MAGIC_COOKIE >> 16),
        struct.unpack("!I", socket.inet_aton(ip))[0] ^ stun.MAGIC_COOKIE,
    )
    return (struct.pack("!HHI", stun.BINDING_RESPONSE, len(attr) + 4, stun.MAGIC_COOKIE)
            + request[8:20] + struct.pack("!HH", stun.XOR_MAPPED_ADDRESS, len(attr)) + attr)


class FakeUdpSocket:
    """Answers binding requests sent to the addresses in `answering`."""

    def __init__(self, answering=(), stray=()):
        self.answering = set(answering)
        self.inbox = list(stray)
        self.sent = []
        self.timeout = None

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, data, addr):
        self.sent.append(addr)
        if addr[0] in self.answering:
            self.inbox.append(binding_response(data))

    def recvfrom(self, size):
        if self.inbox:
            return self.inbox.pop(0), ("198.51.100.1", 3478)
        time.sleep(self.timeout or 0)
        raise socket.timeout()


def discover(sock, resolver=HOSTS.__getitem__, timeout=0.4):
    with mock.patch.object(stun.socket, "gethostbyname", side_effect=resolver):
        start = time.monotonic()
        result = stun.discover_external_address(local_socket=sock, timeout=timeout)
        return result, time.monotonic() - start


class StunDiscoveryTest(unittest.TestCase):
    def test_silent_servers_cost_one_timeout_in_total(self):
        sock = FakeUdpSocket()
        result, elapsed = discover(sock)
        self.assertEqual(result, (None, None))
        self.assertEqual(len(sock.sent), len(stun.STUN_SERVERS))  # all asked at once
        self.assertLess(elapsed, 0.8)

    def test_default_budget_is_short(self):
        self.assertLessEqual(stun.STUN_TOTAL_TIMEOUT, 2.0)

    def test_answer_of_the_last_server_is_used_without_waiting_for_the_others(self):
        last = HOSTS[stun.STUN_SERVERS[-1][0]]
        result, elapsed = discover(FakeUdpSocket(answering=[last]))
        self.assertEqual(result, ("203.0.113.7", 40123))
        self.assertLess(elapsed, 0.3)

    def test_hanging_dns_does_not_extend_the_wait(self):
        def slow(host):
            time.sleep(3)
            return HOSTS[host]

        result, elapsed = discover(FakeUdpSocket(), resolver=slow)
        self.assertEqual(result, (None, None))
        self.assertLess(elapsed, 0.8)

    def test_failing_dns_returns_at_once(self):
        def fail(host):
            raise socket.gaierror("no dns")

        result, elapsed = discover(FakeUdpSocket(), resolver=fail, timeout=2.0)
        self.assertEqual(result, (None, None))
        self.assertLess(elapsed, 0.5)

    def test_foreign_packets_on_the_rtp_socket_are_ignored(self):
        rtp = b"\x80\x08" + b"\x00" * 170
        foreign = binding_response(b"\x00" * 20)  # someone else's transaction
        sock = FakeUdpSocket(answering=HOSTS.values(), stray=[rtp, foreign])
        result, _ = discover(sock)
        self.assertEqual(result, ("203.0.113.7", 40123))

    def test_socket_timeout_is_restored(self):
        sock = FakeUdpSocket()
        sock.settimeout(7)
        discover(sock)
        self.assertEqual(sock.timeout, 7)


class StunOnRtpSocketTest(unittest.TestCase):
    def test_late_stun_answers_are_told_apart_from_rtp(self):
        rh = test_sip_forwarding.rh
        self.assertTrue(rh._is_stun(binding_response(b"\x00" * 20)))
        self.assertFalse(rh._is_stun(b"\x80\x08" + b"\x00" * 170))
        self.assertFalse(rh._is_stun(b""))


if __name__ == "__main__":
    unittest.main()
