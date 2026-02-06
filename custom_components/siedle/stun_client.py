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


def stun_request(sock: socket.socket, stun_server: Tuple[str, int]) -> Tuple[Optional[str], Optional[int]]:
    """
    Send a single STUN Binding Request and parse the response.
    
    Args:
        sock: UDP socket to use (sends from this socket's bound port)
        stun_server: (host, port) of STUN server
        
    Returns:
        (external_ip, external_port) or (None, None)
    """
    # Build STUN Binding Request (RFC 5389)
    # Header: type (2) + length (2) + magic cookie (4) + transaction ID (12) = 20 bytes
    txn_id = os.urandom(12)
    header = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txn_id
    
    old_timeout = sock.gettimeout()
    try:
        sock.settimeout(2)
        sock.sendto(header, stun_server)
        
        data, addr = sock.recvfrom(2048)
        
        if len(data) < 20:
            _LOGGER.warning(f"STUN response too short: {len(data)} bytes")
            return None, None
        
        # Parse response header
        msg_type, msg_len, magic = struct.unpack("!HHI", data[:8])
        resp_txn_id = data[8:20]
        
        if msg_type != BINDING_RESPONSE:
            _LOGGER.warning(f"Unexpected STUN response type: 0x{msg_type:04x}")
            return None, None
        
        if resp_txn_id != txn_id:
            _LOGGER.warning("STUN transaction ID mismatch")
            return None, None
        
        # Parse attributes
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
                    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    _LOGGER.debug(f"STUN XOR-MAPPED-ADDRESS: {ip}:{port}")
                    return ip, port
            
            elif attr_type == MAPPED_ADDRESS and attr_len >= 8:
                # MAPPED-ADDRESS (fallback - RFC 3489)
                family = attr_data[1]
                port = struct.unpack("!H", attr_data[2:4])[0]
                if family == 0x01:  # IPv4
                    ip = socket.inet_ntoa(attr_data[4:8])
                    _LOGGER.debug(f"STUN MAPPED-ADDRESS: {ip}:{port}")
                    return ip, port
            
            # Align to 4-byte boundary
            offset += attr_len + (4 - attr_len % 4) % 4
        
        _LOGGER.warning("No MAPPED-ADDRESS found in STUN response")
        return None, None
        
    except socket.timeout:
        _LOGGER.debug(f"STUN request timed out to {stun_server[0]}:{stun_server[1]}")
        return None, None
    except Exception as e:
        _LOGGER.error(f"STUN request error: {e}")
        return None, None
    finally:
        try:
            sock.settimeout(old_timeout)
        except Exception:
            pass


def discover_external_address(
    local_socket: Optional[socket.socket] = None,
    stun_server: Optional[Tuple[str, int]] = None,
) -> Tuple[Optional[str], Optional[int]]:
    """
    Discover external (public) IP and port using STUN.
    
    If a local_socket is provided, the STUN request is sent from that socket,
    which means the returned external port is the NAT mapping for that specific socket.
    This is crucial for RTP - we need to know how NAT maps our RTP port.
    
    Args:
        local_socket: Existing UDP socket to probe (e.g., RTP socket). 
                       If None, creates a temporary socket.
        stun_server: Specific (host, port) to use. If None, tries multiple servers.
    
    Returns:
        (external_ip, external_port) or (None, None) on failure
    """
    servers = [stun_server] if stun_server else STUN_SERVERS
    
    own_socket = False
    if not local_socket:
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_socket.bind(('0.0.0.0', 0))
        own_socket = True
    
    try:
        for server in servers:
            try:
                # Resolve hostname
                server_ip = socket.gethostbyname(server[0])
                
                # Skip invalid/unroutable resolved addresses
                if server_ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    _LOGGER.debug(f"Skipping STUN server {server[0]} - resolved to invalid IP {server_ip}")
                    continue
                
                _LOGGER.debug(f"Trying STUN server {server[0]} ({server_ip}:{server[1]})")
                
                ip, port = stun_request(local_socket, (server_ip, server[1]))
                if ip and port:
                    _LOGGER.info(f"STUN discovery: external address = {ip}:{port} (via {server[0]})")
                    return ip, port
            except socket.gaierror:
                _LOGGER.debug(f"Could not resolve STUN server: {server[0]}")
                continue
        
        _LOGGER.warning("STUN discovery failed - all servers unreachable")
        return None, None
        
    finally:
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
