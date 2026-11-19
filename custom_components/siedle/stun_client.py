"""Simple STUN client for NAT traversal.

Implements RFC 5389 STUN Binding Request to discover external (public) IP and port.
Used to learn how NAT maps our local RTP ports so we can advertise the correct 
external address in SDP for incoming RTP traffic.

This is the same approach PJSIP uses with contactRewriteUse and viaRewriteUse,
but applied directly to the RTP socket.
"""
import socket
import struct
import os
import logging
import queue
import threading
import time
from typing import Optional, Tuple

_LOGGER = logging.getLogger(__name__)

# STUN constants (RFC 5389)
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101

# STUN Attributes
MAPPED_ADDRESS = 0x0001
XOR_MAPPED_ADDRESS = 0x0020

# Public STUN servers
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.sipgate.net", 3478),
    ("stun.stunprotocol.org", 3478),
]

# Upper bound for one discovery, however many servers stay silent.
STUN_TOTAL_TIMEOUT = 1.5


def _parse_binding_response(data: bytes) -> Tuple[Optional[bytes], Optional[str], Optional[int]]:
    """Parse a STUN Binding Response.

    Returns:
        (transaction_id, external_ip, external_port); all None if the datagram
        is not a binding response carrying an IPv4 mapped address.
    """
    if len(data) < 20:
        return None, None, None

    msg_type, msg_len, _magic = struct.unpack("!HHI", data[:8])
    if msg_type != BINDING_RESPONSE:
        return None, None, None
    txn_id = data[8:20]

    offset = 20
    while offset < 20 + msg_len:
        if offset + 4 > len(data):
            break

        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4

        if offset + attr_len > len(data):
            break

        attr_data = data[offset:offset + attr_len]

        if attr_type == XOR_MAPPED_ADDRESS and attr_len >= 8:
            # XOR-MAPPED-ADDRESS (preferred - RFC 5389)
            family = attr_data[1]
            port = struct.unpack("!H", attr_data[2:4])[0] ^ (MAGIC_COOKIE >> 16)
            if family == 0x01:  # IPv4
                ip_int = struct.unpack("!I", attr_data[4:8])[0] ^ MAGIC_COOKIE
                return txn_id, socket.inet_ntoa(struct.pack("!I", ip_int)), port

        elif attr_type == MAPPED_ADDRESS and attr_len >= 8:
            # MAPPED-ADDRESS (fallback - RFC 3489)
            family = attr_data[1]
            port = struct.unpack("!H", attr_data[2:4])[0]
            if family == 0x01:  # IPv4
                return txn_id, socket.inet_ntoa(attr_data[4:8]), port

        # Align to 4-byte boundary
        offset += attr_len + (4 - attr_len % 4) % 4

    return None, None, None


def discover_external_address(
    local_socket: Optional[socket.socket] = None,
    stun_server: Optional[Tuple[str, int]] = None,
    timeout: float = STUN_TOTAL_TIMEOUT,
) -> Tuple[Optional[str], Optional[int]]:
    """
    Discover external (public) IP and port using STUN.
    
    If a local_socket is provided, the STUN request is sent from that socket,
    which means the returned external port is the NAT mapping for that specific socket.
    This is crucial for RTP - we need to know how NAT maps our RTP port.

    All servers are asked at once and the first answer wins. The caller holds
    the call lock and has not sent the INVITE to the phone yet, so the whole
    discovery, name resolution included, is bounded by `timeout`.
    
    Args:
        local_socket: Existing UDP socket to probe (e.g., RTP socket). 
                       If None, creates a temporary socket.
        stun_server: Specific (host, port) to use. If None, asks all servers.
        timeout: Upper bound in seconds for the whole discovery.
    
    Returns:
        (external_ip, external_port) or (None, None) on failure
    """
    servers = [stun_server] if stun_server else STUN_SERVERS
    
    own_socket = False
    if not local_socket:
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_socket.bind(('0.0.0.0', 0))
        own_socket = True

    # gethostbyname() has no timeout of its own, so it runs off-thread.
    resolved: "queue.SimpleQueue" = queue.SimpleQueue()

    def resolve(server):
        try:
            resolved.put((server, socket.gethostbyname(server[0])))
        except OSError:
            _LOGGER.debug(f"Could not resolve STUN server: {server[0]}")
            resolved.put((server, None))

    for server in servers:
        threading.Thread(target=resolve, args=(server,), daemon=True, name="stun-dns").start()

    unresolved = len(servers)
    pending = {}  # transaction id -> server name
    deadline = time.monotonic() + timeout
    old_timeout = local_socket.gettimeout()
    try:
        while True:
            while True:
                try:
                    server, server_ip = resolved.get_nowait()
                except queue.Empty:
                    break
                unresolved -= 1
                # Skip unresolved and invalid/unroutable addresses
                if server_ip in (None, "0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    continue
                # Header: type (2) + length (2) + magic cookie (4) + transaction ID (12)
                txn_id = os.urandom(12)
                try:
                    local_socket.sendto(
                        struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txn_id,
                        (server_ip, server[1]),
                    )
                    pending[txn_id] = server[0]
                except OSError as e:
                    _LOGGER.debug(f"STUN request to {server[0]} failed: {e}")

            if not unresolved and not pending:
                break  # nobody left who could answer
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            local_socket.settimeout(min(remaining, 0.05))
            try:
                data, _addr = local_socket.recvfrom(2048)
            except socket.timeout:
                continue
            # Anything else arriving on the RTP socket is not ours to judge.
            txn_id, ip, port = _parse_binding_response(data)
            if txn_id in pending and ip and port:
                _LOGGER.info(f"STUN discovery: external address = {ip}:{port} (via {pending[txn_id]})")
                return ip, port

        _LOGGER.warning("STUN discovery failed - no server answered within %.1f s", timeout)
        return None, None
    except OSError as e:
        _LOGGER.error(f"STUN discovery error: {e}")
        return None, None
    finally:
        try:
            local_socket.settimeout(old_timeout)
        except Exception:
            pass
        if own_socket:
            local_socket.close()


def get_external_ip() -> Optional[str]:
    """
    Quick helper to just get external IP without caring about port.
    
    Returns:
        External IP string or None
    """
    ip, _ = discover_external_address()
    return ip
