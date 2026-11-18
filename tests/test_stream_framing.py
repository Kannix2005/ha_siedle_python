"""SIP over TCP/TLS has no message boundaries; framing must use Content-Length."""
import socket
import unittest

from test_sip_forwarding import sm

SDP = "v=0\r\nc=IN IP4 192.168.178.1\r\nm=audio 7078 RTP/AVP 8 101\r\n"
OK = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/TCP 10.10.10.3:40000;branch=z9hG4bK1\r\n"
    "Call-ID: c1\r\nCSeq: 2 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    f"Content-Length: {len(SDP)}\r\n\r\n{SDP}"
).encode()
BYE = (
    "BYE sip:tuer@10.10.10.3:40000 SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 192.168.178.1:5060;branch=z9hG4bK2\r\n"
    "Call-ID: c1\r\nCSeq: 3 BYE\r\nContent-Length: 0\r\n\r\n"
).encode()


class ChunkSocket:
    """Hands out the given chunks, one per recv(), then times out."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def setblocking(self, flag):
        pass

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        if not self.chunks:
            raise socket.timeout()
        return self.chunks.pop(0)


def connection(chunks, transport=sm.SipTransport.TCP):
    cfg = sm.SipConfig(host="192.168.178.1", port=5060, username="tuer",
                       password="pw", transport=transport)
    conn = sm.SipConnection(cfg, "External-SIP")
    conn._socket = ChunkSocket(chunks)
    conn._wait_readable = lambda sock, timeout: True  # no real fd
    conn._running = True
    return conn


def drain(conn, calls=6):
    return [m for m in (conn.recv() for _ in range(calls)) if m]


class StreamFramingTest(unittest.TestCase):
    def test_response_split_inside_headers_keeps_its_sdp(self):
        msgs = drain(connection([OK[:150], OK[150:]]))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].status_code, 200)
        self.assertEqual(msgs[0].get_sdp_media_port(), 7078)

    def test_response_split_inside_body_keeps_its_sdp(self):
        msgs = drain(connection([OK[:-10], OK[-10:]]))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].get_sdp_connection_ip(), "192.168.178.1")

    def test_two_messages_in_one_segment_are_both_delivered(self):
        msgs = drain(connection([OK + BYE]))
        self.assertEqual([(m.status_code, m.method) for m in msgs], [(200, None), (None, "BYE")])

    def test_keepalive_crlf_between_messages_is_skipped(self):
        msgs = drain(connection([b"\r\n\r\n" + BYE[:20], BYE[20:]]))
        self.assertEqual([m.method for m in msgs], ["BYE"])

    def test_announced_oversized_body_gives_up_the_connection(self):
        # Skipping ahead is not safe: the body bytes would be read as messages.
        huge = b"MESSAGE sip:tuer@10.10.10.3 SIP/2.0\r\nCall-ID: x\r\nContent-Length: 99999999\r\n\r\n"
        conn = connection([huge + BYE])
        self.assertIsNone(conn.recv())
        self.assertTrue(conn._connection_lost)
        self.assertEqual(conn._rx_buffer, b"")

    def test_stream_without_boundary_gives_up_the_connection(self):
        conn = connection([b"A" * (sm.SipConnection.MAX_RX_BUFFER + 1)])
        self.assertIsNone(conn.recv())
        self.assertTrue(conn._connection_lost)

    def test_udp_datagrams_are_parsed_as_they_arrive(self):
        msgs = drain(connection([BYE], transport=sm.SipTransport.UDP))
        self.assertEqual([m.method for m in msgs], ["BYE"])


if __name__ == "__main__":
    unittest.main()
