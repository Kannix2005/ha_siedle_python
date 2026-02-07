"""SIP Call Manager for Siedle integration.

Handles SIP signaling between Siedle door station and external SIP servers.
Supports call forwarding, answering, and audio bridging.
"""
import asyncio
import logging
import socket
import ssl
import hashlib
import uuid
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Dict, Any, List, Tuple
import ipaddress

_LOGGER = logging.getLogger(__name__)


def _is_private_ip(host: str) -> bool:
    """Check if a host/IP is on a private (RFC 1918) network."""
    try:
        # Resolve hostname to IP if needed
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except (socket.gaierror, ValueError):
        _LOGGER.warning(f"Cannot determine if {host} is private, assuming public")
        return False


class CallState(Enum):
    """Call state enumeration."""
    IDLE = "idle"
    RINGING_IN = "ringing_in"  # Incoming call ringing
    RINGING_OUT = "ringing_out"  # Outgoing call ringing
    CONNECTED = "connected"
    RECORDING = "recording"
    ENDING = "ending"


class SipTransport(Enum):
    """SIP transport protocol."""
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


@dataclass
class SipConfig:
    """SIP server configuration."""
    host: str
    port: int
    username: str
    password: str
    transport: SipTransport = SipTransport.UDP
    realm: Optional[str] = None
    display_name: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: dict) -> "SipConfig":
        """Create from dictionary.
        
        Siedle SIP config format (from /api/endpoint/v1/endpoint/config):
        {
            "host": "sus2-sip.siedle.com",
            "port": 5061,
            "username": "...",
            "password": "...",
            "protocol": "ssl"  # or "tls"
        }
        """
        # Get transport - Siedle uses "ssl" or "protocol" field
        transport = data.get("transport", data.get("protocol", "")).lower()
        
        # Default to TLS for Siedle SIP server (sus2-sip.siedle.com uses TLS on port 5061)
        if not transport:
            host = data.get("host", "")
            port = data.get("port", 5060)
            # Siedle server always uses TLS
            if "siedle" in host.lower() or port == 5061:
                transport = "tls"
            else:
                transport = "udp"
        
        # Normalize transport
        if transport in ("ssl", "tls"):
            transport = "tls"
        elif transport == "tcp":
            transport = "tcp"
        else:
            transport = "udp"
        
        _LOGGER.debug(f"SipConfig.from_dict: host={data.get('host')}, port={data.get('port')}, transport={transport}")
        
        return cls(
            host=data["host"],
            port=data.get("port", 5060),
            username=data["username"],
            password=data["password"],
            transport=SipTransport(transport),
            display_name=data.get("display_name"),
        )


@dataclass
class SipCall:
    """Represents an active SIP call."""
    call_id: str
    from_uri: str
    to_uri: str
    from_tag: str
    to_tag: Optional[str] = None
    state: CallState = CallState.IDLE
    local_rtp_port: int = 0
    remote_rtp_host: Optional[str] = None
    remote_rtp_port: int = 0
    cseq: int = 1
    via_branch: str = field(default_factory=lambda: f"z9hG4bK-{uuid.uuid4().hex[:12]}")
    sdp_session_id: str = field(default_factory=lambda: str(int(time.time())))
    invite_data: Optional[bytes] = None  # Store original INVITE for response
    
    def next_cseq(self) -> int:
        """Get and increment CSeq."""
        current = self.cseq
        self.cseq += 1
        return current


@dataclass
class SipMessage:
    """Parsed SIP message."""
    raw: str
    is_request: bool
    method: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    uri: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    header_list: List[Tuple[str, str]] = field(default_factory=list)  # Preserve ALL headers in order
    body: str = ""
    
    @property
    def call_id(self) -> Optional[str]:
        return self.headers.get("Call-ID") or self.headers.get("i")
    
    @property
    def from_header(self) -> Optional[str]:
        return self.headers.get("From") or self.headers.get("f")
    
    @property
    def to_header(self) -> Optional[str]:
        return self.headers.get("To") or self.headers.get("t")
    
    @property
    def via(self) -> Optional[str]:
        """First (topmost) Via header."""
        vias = self.via_list
        return vias[0] if vias else (self.headers.get("Via") or self.headers.get("v"))
    
    @property
    def via_list(self) -> List[str]:
        """All Via headers in order (topmost first). Critical for SIP responses."""
        return [v for k, v in self.header_list if k == "Via" or k == "v"]
    
    @property
    def record_route_list(self) -> List[str]:
        """All Record-Route headers in order."""
        return [v for k, v in self.header_list if k == "Record-Route"]
    
    @property
    def cseq(self) -> Optional[str]:
        return self.headers.get("CSeq")
    
    @property
    def contact(self) -> Optional[str]:
        return self.headers.get("Contact") or self.headers.get("m")
    
    def get_sdp_media_port(self) -> Optional[int]:
        """Extract RTP port from SDP body."""
        if not self.body:
            return None
        match = re.search(r'm=audio\s+(\d+)', self.body)
        return int(match.group(1)) if match else None
    
    def get_sdp_connection_ip(self) -> Optional[str]:
        """Extract connection IP from SDP body."""
        if not self.body:
            return None
        match = re.search(r'c=IN\s+IP4\s+([\d.]+)', self.body)
        return match.group(1) if match else None


class SipConnection:
    """Manages a single SIP connection to a server."""
    
    def __init__(self, config: SipConfig, name: str = "SIP"):
        self.config = config
        self.name = name
        self._socket: Optional[socket.socket] = None
        self._ssl_socket: Optional[ssl.SSLSocket] = None
        self._connected = False
        self._registered = False
        self._local_ip: Optional[str] = None
        self._local_port = 5060
        self._call_id = str(uuid.uuid4())
        self._from_tag = uuid.uuid4().hex[:8]  # Keep same tag for all REGISTERs
        self._cseq = 0
        self._realm: Optional[str] = None
        self._nonce: Optional[str] = None
        self._callbacks: List[Callable[[SipMessage], None]] = []
        self._running = False
        self._listen_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        
        # NAT traversal: external IP learned from Via received= or STUN
        self._external_ip: Optional[str] = None
        self._external_port: Optional[int] = None
        
        # Keepalive / re-registration
        self._last_recv_time: float = 0.0
        self._last_register_time: float = 0.0
        self._connection_lost = False
        # Re-register interval: 300s (well before 3600s Expires)
        self.re_register_interval: int = 300
        # Keepalive: send OPTIONS every 30s to detect dead TLS connections
        self.keepalive_interval: int = 30
        # If no data received for 120s (including keepalive responses), connection is likely dead
        self.recv_timeout: int = 120
        
    @property
    def registered(self) -> bool:
        return self._registered
    
    @property
    def connected(self) -> bool:
        return self._connected
    
    @property
    def external_ip(self) -> Optional[str]:
        """Public IP as seen by SIP server (from Via received= or STUN)."""
        return self._external_ip
    
    @property
    def external_port(self) -> Optional[int]:
        """Public port as seen by SIP server."""
        return self._external_port
    
    def _extract_via_received(self, msg: SipMessage):
        """Extract received= and rport= from Via header to learn our public IP.
        
        The SIP server adds these parameters to tell us what IP:port it sees.
        PJSIP uses this with contactRewriteUse(1) and viaRewriteUse(1).
        """
        via = msg.via
        if not via:
            return
        
        # Extract received= (our public IP as seen by server)
        received_match = re.search(r'received=([^;,\s]+)', via)
        if received_match:
            old_ip = self._external_ip
            self._external_ip = received_match.group(1)
            if old_ip != self._external_ip:
                _LOGGER.info(f"{self.name}: NAT detected! Public IP: {self._external_ip} (local: {self._get_local_ip()})")
        
        # Extract rport= (our public port as seen by server)
        rport_match = re.search(r'rport=(\d+)', via)
        if rport_match:
            self._external_port = int(rport_match.group(1))
            _LOGGER.debug(f"{self.name}: Public port: {self._external_port}")
    
    def get_sdp_ip(self) -> str:
        """Get the IP to use in SDP - external IP if behind NAT, else local."""
        if self._external_ip:
            return self._external_ip
        return self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        if self._local_ip:
            return self._local_ip
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.config.host, 80))
            self._local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self._local_ip = "192.168.1.100"
        return self._local_ip
    
    def _next_cseq(self) -> int:
        """Get next CSeq number."""
        self._cseq += 1
        return self._cseq
    
    def _compute_digest(self, method: str, uri: str) -> str:
        """Compute Digest authentication response."""
        if not self._realm or not self._nonce:
            return ""
        ha1 = hashlib.md5(
            f"{self.config.username}:{self._realm}:{self.config.password}".encode()
        ).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{self._nonce}:{ha2}".encode()).hexdigest()
        return response
    
    def add_callback(self, callback: Callable[[SipMessage], None]):
        """Add message callback."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[SipMessage], None]):
        """Remove message callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def _notify_callbacks(self, message: SipMessage):
        """Notify all callbacks of received message."""
        for callback in self._callbacks:
            try:
                callback(message)
            except Exception as e:
                _LOGGER.error(f"{self.name}: Callback error: {e}")
    
    @staticmethod
    def parse_message(data: bytes) -> SipMessage:
        """Parse a SIP message."""
        try:
            text = data.decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            
            msg = SipMessage(raw=text, is_request=False)
            
            if not lines:
                return msg
            
            # Parse first line
            first_line = lines[0]
            if first_line.startswith("SIP/2.0"):
                # Response
                parts = first_line.split(" ", 2)
                msg.status_code = int(parts[1]) if len(parts) > 1 else 0
                msg.status_text = parts[2] if len(parts) > 2 else ""
            else:
                # Request
                msg.is_request = True
                parts = first_line.split(" ")
                msg.method = parts[0] if parts else None
                msg.uri = parts[1] if len(parts) > 1 else None
            
            # Parse headers - preserve ALL headers in order (critical for multi-value headers like Via)
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    name, value = line.split(":", 1)
                    name_s = name.strip()
                    value_s = value.strip()
                    msg.headers[name_s] = value_s  # Last-wins for single-value access
                    msg.header_list.append((name_s, value_s))  # Preserve all in order
            
            # Parse body (SDP)
            if body_start > 0 and body_start < len(lines):
                msg.body = "\r\n".join(lines[body_start:])
            
            return msg
            
        except Exception as e:
            _LOGGER.error(f"Error parsing SIP message: {e}")
            return SipMessage(raw=data.decode('utf-8', errors='replace'), is_request=False)
    
    def _create_register(self, with_auth: bool = False) -> bytes:
        """Create SIP REGISTER message."""
        local_ip = self._get_local_ip()
        cseq = self._next_cseq()
        branch = uuid.uuid4().hex[:12]
        uri = f"sip:{self.config.host}"
        
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        lines = [
            f"REGISTER {uri} SIP/2.0",
            f"Via: SIP/2.0/{transport_str} {local_ip}:{self._local_port};rport;branch=z9hG4bK-{branch}",
            "Max-Forwards: 70",
            f"From: <sip:{self.config.username}@{self.config.host}>;tag={self._from_tag}",
            f"To: <sip:{self.config.username}@{self.config.host}>",
            f"Call-ID: {self._call_id}@{local_ip}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: <sip:{self.config.username}@{local_ip}:{self._local_port};transport={transport_str.lower()}>",
            f"User-Agent: Siedle-HA/1.0",
            "Expires: 3600",
            "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE",
        ]
        
        if with_auth and self._realm and self._nonce:
            response = self._compute_digest("REGISTER", uri)
            lines.append(
                f'Authorization: Digest username="{self.config.username}", '
                f'realm="{self._realm}", '
                f'nonce="{self._nonce}", '
                f'uri="{uri}", '
                f'response="{response}", '
                f'algorithm=MD5'
            )
        
        lines.extend(["Content-Length: 0", "", ""])
        return "\r\n".join(lines).encode('utf-8')
    
    def create_invite(self, to_uri: str, local_rtp_port: int, call_id: Optional[str] = None,
                      sdp_override: Optional[str] = None) -> Tuple[bytes, SipCall]:
        """Create SIP INVITE message with SDP.
        
        Args:
            to_uri: Target SIP URI
            local_rtp_port: RTP port for default SDP
            call_id: Optional Call-ID
            sdp_override: Optional custom SDP body (replaces default SDP)
        """
        local_ip = self._get_local_ip()
        call_id = call_id or str(uuid.uuid4())
        from_tag = uuid.uuid4().hex[:8]
        branch = uuid.uuid4().hex[:12]
        cseq = 1
        
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        display_name = self.config.display_name or "Siedle Türstation"
        
        # Use custom SDP or generate default
        if sdp_override:
            sdp = sdp_override
        else:
            # Create default SDP body
            session_id = str(int(time.time()))
            sdp = (
                f"v=0\r\n"
                f"o=- {session_id} {session_id} IN IP4 {local_ip}\r\n"
                f"s=Siedle Call\r\n"
                f"c=IN IP4 {local_ip}\r\n"
                f"t=0 0\r\n"
                f"m=audio {local_rtp_port} RTP/AVP 0 8 101\r\n"
                f"a=rtpmap:0 PCMU/8000\r\n"
                f"a=rtpmap:8 PCMA/8000\r\n"
                f"a=rtpmap:101 telephone-event/8000\r\n"
                f"a=fmtp:101 0-16\r\n"
                f"a=sendrecv\r\n"
            )
        
        lines = [
            f"INVITE {to_uri} SIP/2.0",
            f"Via: SIP/2.0/{transport_str} {local_ip}:{self._local_port};rport;branch=z9hG4bK-{branch}",
            "Max-Forwards: 70",
            f'From: "{display_name}" <sip:{self.config.username}@{self.config.host}>;tag={from_tag}',
            f"To: <{to_uri}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} INVITE",
            f"Contact: <sip:{self.config.username}@{local_ip}:{self._local_port};transport={transport_str.lower()}>",
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp)}",
            "",
            sdp,
        ]
        
        call = SipCall(
            call_id=call_id,
            from_uri=f"sip:{self.config.username}@{self.config.host}",
            to_uri=to_uri,
            from_tag=from_tag,
            local_rtp_port=local_rtp_port,
            state=CallState.RINGING_OUT,
        )
        
        return "\r\n".join(lines).encode('utf-8'), call
    
    def create_response(self, request: SipMessage, status_code: int, status_text: str, 
                       sdp: Optional[str] = None, local_rtp_port: int = 0) -> bytes:
        """Create SIP response to a request.
        
        RFC 3261 §8.2.6.2: Response MUST contain all Via headers from the request.
        Record-Route headers must also be copied for dialog-establishing responses.
        """
        local_ip = self._get_local_ip()
        to_tag = uuid.uuid4().hex[:8]
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        # Build To header with tag for 200 OK
        to_header = request.to_header
        if status_code == 200 and ";tag=" not in to_header:
            to_header = f"{to_header};tag={to_tag}"
        
        lines = [f"SIP/2.0 {status_code} {status_text}"]
        
        # RFC 3261 §8.2.6.2: Copy ALL Via headers from request (order preserved)
        via_list = request.via_list
        if via_list:
            for via in via_list:
                lines.append(f"Via: {via}")
            if len(via_list) > 1:
                _LOGGER.info(f"Response includes {len(via_list)} Via headers (multi-hop)")
        else:
            # Fallback: single via from dict
            lines.append(f"Via: {request.via}")
        
        # Copy Record-Route headers for dialog-establishing responses (200 OK to INVITE)
        if status_code == 200 and request.method == "INVITE":
            for rr in request.record_route_list:
                lines.append(f"Record-Route: {rr}")
        
        lines.extend([
            f"From: {request.from_header}",
            f"To: {to_header}",
            f"Call-ID: {request.call_id}",
            f"CSeq: {request.cseq}",
        ])
        
        if status_code == 200 and request.method == "INVITE":
            lines.append(f"Contact: <sip:{self.config.username}@{local_ip}:{self._local_port};transport={transport_str.lower()}>")
            lines.append("Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE")
            lines.append("User-Agent: Siedle-HA/1.0")
        
        if sdp:
            lines.extend([
                "Content-Type: application/sdp",
                f"Content-Length: {len(sdp)}",
                "",
                sdp,
            ])
        else:
            lines.extend(["Content-Length: 0", "", ""])
        
        return "\r\n".join(lines).encode('utf-8')
    
    def create_bye(self, call: SipCall) -> bytes:
        """Create SIP BYE message."""
        local_ip = self._get_local_ip()
        cseq = call.next_cseq()
        branch = uuid.uuid4().hex[:12]
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        to_header = f"<{call.to_uri}>"
        if call.to_tag:
            to_header = f"<{call.to_uri}>;tag={call.to_tag}"
        
        lines = [
            f"BYE {call.to_uri} SIP/2.0",
            f"Via: SIP/2.0/{transport_str} {local_ip}:{self._local_port};rport;branch=z9hG4bK-{branch}",
            "Max-Forwards: 70",
            f"From: <{call.from_uri}>;tag={call.from_tag}",
            f"To: {to_header}",
            f"Call-ID: {call.call_id}",
            f"CSeq: {cseq} BYE",
            "Content-Length: 0",
            "",
            "",
        ]
        
        return "\r\n".join(lines).encode('utf-8')
    
    def create_ack(self, call: SipCall, for_response: SipMessage) -> bytes:
        """Create SIP ACK message."""
        local_ip = self._get_local_ip()
        branch = uuid.uuid4().hex[:12]
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        # Extract to_tag from response
        to_header = for_response.to_header
        
        lines = [
            f"ACK {call.to_uri} SIP/2.0",
            f"Via: SIP/2.0/{transport_str} {local_ip}:{self._local_port};rport;branch=z9hG4bK-{branch}",
            "Max-Forwards: 70",
            f"From: <{call.from_uri}>;tag={call.from_tag}",
            f"To: {to_header}",
            f"Call-ID: {call.call_id}",
            f"CSeq: {call.cseq} ACK",  # Same CSeq as INVITE
            "Content-Length: 0",
            "",
            "",
        ]
        
        return "\r\n".join(lines).encode('utf-8')

    def connect(self) -> bool:
        """Connect to SIP server."""
        try:
            _LOGGER.info(f"{self.name}: Connecting to {self.config.host}:{self.config.port} ({self.config.transport.value})...")
            
            if self.config.transport == SipTransport.TLS:
                # TLS connection
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                self._ssl_socket = context.wrap_socket(sock, server_hostname=self.config.host)
                self._ssl_socket.connect((self.config.host, self.config.port))
                self._socket = self._ssl_socket
                _LOGGER.info(f"{self.name}: TLS connection established")
            elif self.config.transport == SipTransport.TCP:
                # TCP connection
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(30)
                self._socket.connect((self.config.host, self.config.port))
                _LOGGER.info(f"{self.name}: TCP connection established")
            else:
                # UDP connection
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(5)
                # For UDP, we don't "connect" but we set default destination
                self._socket.connect((self.config.host, self.config.port))
                _LOGGER.info(f"{self.name}: UDP socket ready")
            
            self._connected = True
            return True
            
        except Exception as e:
            _LOGGER.error(f"{self.name}: Connection failed: {e}")
            self._connected = False
            return False
    
    def register(self) -> bool:
        """Register with SIP server."""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            # Send initial REGISTER
            _LOGGER.info(f"{self.name}: Sending initial REGISTER to {self.config.host}:{self.config.port}...")
            register_msg = self._create_register(with_auth=False)
            _LOGGER.debug(f"{self.name}: REGISTER message:\n{register_msg.decode()[:500]}...")
            self._socket.send(register_msg)
            
            response = self._socket.recv(4096)
            msg = self.parse_message(response)
            _LOGGER.info(f"{self.name}: Response: {msg.status_code} {msg.status_text}")
            
            # Learn external IP from Via received= parameter
            self._extract_via_received(msg)
            
            if msg.status_code == 401 or msg.status_code == 407:
                # Extract auth params
                www_auth = msg.headers.get("WWW-Authenticate") or msg.headers.get("Proxy-Authenticate", "")
                _LOGGER.info(f"{self.name}: Auth required - extracting credentials from WWW-Authenticate header")
                _LOGGER.debug(f"{self.name}: Auth header: {www_auth}")
                
                if not www_auth:
                    _LOGGER.error(f"{self.name}: No WWW-Authenticate header found! Headers: {list(msg.headers.keys())}")
                    _LOGGER.error(f"{self.name}: Full response:\n{msg.raw[:1000]}")
                    return False
                
                realm_match = re.search(r'realm="([^"]+)"', www_auth)
                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                
                if realm_match and nonce_match:
                    self._realm = realm_match.group(1)
                    self._nonce = nonce_match.group(1)
                    _LOGGER.info(f"{self.name}: Extracted realm={self._realm}, nonce={self._nonce[:20]}...")
                    
                    # Authenticated REGISTER
                    _LOGGER.info(f"{self.name}: Sending authenticated REGISTER...")
                    auth_register = self._create_register(with_auth=True)
                    _LOGGER.debug(f"{self.name}: Auth REGISTER message:\n{auth_register.decode()[:800]}...")
                    self._socket.send(auth_register)
                    
                    response = self._socket.recv(4096)
                    msg = self.parse_message(response)
                    _LOGGER.info(f"{self.name}: Auth response: {msg.status_code} {msg.status_text}")
                    
                    # Learn external IP from Via received= parameter
                    self._extract_via_received(msg)
                    
                    if msg.status_code == 200:
                        _LOGGER.info(f"{self.name}: Registration successful!")
                        self._registered = True
                        
                        # If we still don't know external IP, try STUN
                        if not self._external_ip:
                            self._discover_external_ip_via_stun()
                        
                        if self._external_ip:
                            _LOGGER.info(f"{self.name}: Will use external IP {self._external_ip} in SDP for NAT traversal")
                        else:
                            _LOGGER.warning(f"{self.name}: Could not determine external IP - RTP may fail behind NAT")
                        
                        return True
                    else:
                        _LOGGER.error(f"{self.name}: Registration failed: {msg.status_code} {msg.status_text}")
                        _LOGGER.error(f"{self.name}: Response body: {msg.raw[:500]}")
                        return False
                else:
                    _LOGGER.error(f"{self.name}: Could not extract realm/nonce from: {www_auth}")
            elif msg.status_code == 200:
                _LOGGER.info(f"{self.name}: Registration successful (no auth needed)")
                self._registered = True
                
                # If we still don't know external IP, try STUN
                if not self._external_ip:
                    self._discover_external_ip_via_stun()
                
                return True
            else:
                _LOGGER.error(f"{self.name}: Unexpected response: {msg.status_code}")
                return False
                
        except Exception as e:
            _LOGGER.error(f"{self.name}: Registration error: {e}")
            return False
    
    def send(self, data: bytes):
        """Send data to server."""
        if self._socket:
            self._socket.send(data)
    
    def _discover_external_ip_via_stun(self):
        """Use STUN to discover our public IP address."""
        try:
            from .stun_client import discover_external_address
            _LOGGER.info(f"{self.name}: Attempting STUN discovery for external IP...")
            ip, port = discover_external_address()
            if ip:
                self._external_ip = ip
                self._external_port = port
                _LOGGER.info(f"{self.name}: STUN discovered external address: {ip}:{port}")
            else:
                _LOGGER.warning(f"{self.name}: STUN discovery failed - no external IP found")
        except ImportError:
            _LOGGER.warning(f"{self.name}: STUN client not available")
        except Exception as e:
            _LOGGER.error(f"{self.name}: STUN discovery error: {e}")
    
    def recv(self, timeout: float = 0.1) -> Optional[SipMessage]:
        """Receive and parse message with timeout."""
        try:
            if self.config.transport != SipTransport.UDP:
                self._socket.setblocking(False)
            self._socket.settimeout(timeout)
            data = self._socket.recv(4096)
            if data:
                self._last_recv_time = time.time()
                return self.parse_message(data)
            else:
                # Empty data = connection closed by peer
                if self._running:
                    _LOGGER.warning(f"{self.name}: Connection closed by remote (empty recv)")
                    self._connection_lost = True
                return None
        except socket.timeout:
            pass
        except ssl.SSLWantReadError:
            pass
        except BlockingIOError:
            pass
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            if self._running:
                _LOGGER.warning(f"{self.name}: Connection lost: {e}")
                self._connection_lost = True
        except ssl.SSLError as e:
            if self._running:
                _LOGGER.warning(f"{self.name}: TLS error (connection may be dead): {e}")
                self._connection_lost = True
        except OSError as e:
            if self._running:
                _LOGGER.warning(f"{self.name}: Socket error: {e}")
                self._connection_lost = True
        except Exception as e:
            if self._running:
                _LOGGER.debug(f"{self.name}: Receive error: {e}")
        return None
    
    def start_listen_loop(self):
        """Start background listen loop."""
        if self._listen_thread and self._listen_thread.is_alive():
            return
        
        self._running = True
        self._connection_lost = False
        self._last_recv_time = time.time()
        self._last_register_time = time.time()
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()
        
        # Start keepalive thread
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._keepalive_thread.start()
    
    def _listen_loop(self):
        """Background listen loop."""
        _LOGGER.info(f"{self.name}: Listen loop started - waiting for incoming SIP messages...")
        while self._running and not self._connection_lost:
            msg = self.recv(timeout=0.5)
            if msg and (msg.method or msg.status_code):
                _LOGGER.debug(f"{self.name}: Received: method={msg.method}, status={msg.status_code}")
                
                # Filter responses to keepalive/re-register (OPTIONS, REGISTER)
                # Only forward INVITE/BYE/ACK/CANCEL related responses to callbacks
                if not msg.is_request and msg.status_code:
                    cseq_header = msg.cseq or ""
                    cseq_method = cseq_header.split()[-1] if cseq_header.strip() else ""
                    if cseq_method == "OPTIONS":
                        # Keepalive response — silently ignore
                        continue
                    elif cseq_method == "REGISTER":
                        if msg.status_code == 200:
                            _LOGGER.debug(f"{self.name}: Re-REGISTER successful")
                        elif msg.status_code in (401, 407):
                            # Nonce expired — extract new nonce and retry
                            self._handle_register_auth_challenge(msg)
                        else:
                            _LOGGER.debug(f"{self.name}: REGISTER response {msg.status_code}")
                        continue
                
                self._notify_callbacks(msg)
        if self._connection_lost:
            _LOGGER.warning(f"{self.name}: Listen loop ended — connection lost, notifying for reconnect")
        else:
            _LOGGER.info(f"{self.name}: Listen loop ended")
    
    def _handle_register_auth_challenge(self, msg: SipMessage):
        """Handle 401/407 from REGISTER by extracting new nonce and retrying."""
        is_proxy = (msg.status_code == 407)
        auth_header_name = "Proxy-Authenticate" if is_proxy else "WWW-Authenticate"
        auth_value = msg.headers.get(auth_header_name, "")
        if not auth_value:
            auth_value = msg.headers.get("WWW-Authenticate") or msg.headers.get("Proxy-Authenticate", "")
        
        realm_match = re.search(r'realm="([^"]+)"', auth_value)
        nonce_match = re.search(r'nonce="([^"]+)"', auth_value)
        
        if realm_match and nonce_match:
            self._realm = realm_match.group(1)
            self._nonce = nonce_match.group(1)
            _LOGGER.debug(f"{self.name}: Got new nonce from REGISTER {msg.status_code}, retrying re-REGISTER...")
            try:
                self._send_re_register()
            except Exception as e:
                _LOGGER.warning(f"{self.name}: Re-REGISTER retry failed: {e}")
        else:
            _LOGGER.debug(f"{self.name}: REGISTER {msg.status_code} without parseable auth header")
    
    def _keepalive_loop(self):
        """Periodic keepalive and re-registration loop."""
        _LOGGER.info(f"{self.name}: Keepalive loop started (OPTIONS every {self.keepalive_interval}s, re-REGISTER every {self.re_register_interval}s)")
        while self._running and not self._connection_lost:
            time.sleep(1)
            now = time.time()
            
            # Check for receive timeout (possible dead connection)
            if self._last_recv_time > 0 and (now - self._last_recv_time) > self.recv_timeout:
                _LOGGER.warning(f"{self.name}: No data received for {int(now - self._last_recv_time)}s — connection likely dead")
                self._connection_lost = True
                break
            
            # Send OPTIONS keepalive
            if (now - self._last_recv_time) > self.keepalive_interval:
                try:
                    self._send_options_keepalive()
                except Exception as e:
                    _LOGGER.warning(f"{self.name}: Failed to send keepalive OPTIONS: {e}")
                    self._connection_lost = True
                    break
            
            # Re-register periodically
            if (now - self._last_register_time) > self.re_register_interval:
                try:
                    _LOGGER.info(f"{self.name}: Sending re-REGISTER (periodic refresh)...")
                    self._send_re_register()
                    self._last_register_time = now
                except Exception as e:
                    _LOGGER.warning(f"{self.name}: Re-REGISTER failed: {e}")
                    self._connection_lost = True
                    break
        
        _LOGGER.info(f"{self.name}: Keepalive loop ended (connection_lost={self._connection_lost})")
    
    def _send_options_keepalive(self):
        """Send SIP OPTIONS as keepalive to detect dead connections."""
        if not self._socket or not self._connected:
            return
        local_ip = self._get_local_ip()
        cseq = self._next_cseq()
        branch = uuid.uuid4().hex[:12]
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        options_msg = (
            f"OPTIONS sip:{self.config.host} SIP/2.0\r\n"
            f"Via: SIP/2.0/{transport_str} {local_ip}:{self._local_port};rport;branch=z9hG4bK-{branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{self.config.username}@{self.config.host}>;tag={self._from_tag}\r\n"
            f"To: <sip:{self.config.host}>\r\n"
            f"Call-ID: {self._call_id}@{local_ip}\r\n"
            f"CSeq: {cseq} OPTIONS\r\n"
            f"User-Agent: Siedle-HA/1.0\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        self._socket.send(options_msg.encode('utf-8'))
    
    def _send_re_register(self):
        """Send a re-REGISTER to refresh registration."""
        if not self._socket or not self._connected:
            return
        # Send authenticated REGISTER (we already have realm/nonce from initial auth)
        register_msg = self._create_register(with_auth=True)
        self._socket.send(register_msg)
        _LOGGER.debug(f"{self.name}: Re-REGISTER sent")
    
    def stop(self):
        """Stop connection and listen loop."""
        self._running = False
        self._registered = False
        self._connected = False
        self._connection_lost = True
        
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
        
        # Wait for threads to end
        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=3.0)
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            self._keepalive_thread.join(timeout=3.0)
        
        _LOGGER.info(f"{self.name}: Connection closed")
    
    @property
    def connection_lost(self) -> bool:
        """True if the connection was detected as dead."""
        return self._connection_lost


class SipCallManager:
    """
    Manages SIP calls between Siedle door station and external SIP servers.
    
    Features:
    - Doorbell detection via SIP INVITE
    - Call forwarding to external SIP server
    - Incoming calls from external server to door station
    - Call recording
    """
    
    def __init__(
        self,
        siedle_config: SipConfig,
        external_config: Optional[SipConfig] = None,
        forward_to_number: Optional[str] = None,
        forward_from_number: Optional[str] = None,
        auto_answer: bool = False,
        recording_enabled: bool = False,
        recording_path: Optional[str] = None,
        recording_duration: Optional[int] = None,
        # F1: Call Timeout
        forward_timeout: int = 30,
        # F6: Time-Based Forwarding
        forward_schedule_enabled: bool = False,
        forward_schedule_start: str = "00:00",
        forward_schedule_end: str = "23:59",
        forward_schedule_days: Optional[List[int]] = None,
        # F7: Announcement
        announcement_enabled: bool = False,
        announcement_file: Optional[str] = None,
        # F8: DTMF Door Opener
        dtmf_enabled: bool = False,
        dtmf_door_code: str = "#",
        dtmf_light_code: str = "*",
        # F12: Doorbell Buttons
        doorbell_buttons: Optional[List[Dict[str, str]]] = None,
    ):
        self.siedle_config = siedle_config
        self.external_config = external_config
        self.forward_to_number = forward_to_number
        self.forward_from_number = forward_from_number
        self.auto_answer = auto_answer
        self.recording_enabled = recording_enabled
        self.recording_path = recording_path
        self.recording_duration = recording_duration
        
        # F1: Call Timeout
        self.forward_timeout = forward_timeout
        self._forward_timeout_timer: Optional[threading.Timer] = None
        
        # F6: Time-Based Forwarding
        self.forward_schedule_enabled = forward_schedule_enabled
        self.forward_schedule_start = forward_schedule_start
        self.forward_schedule_end = forward_schedule_end
        self.forward_schedule_days = forward_schedule_days or [0, 1, 2, 3, 4, 5, 6]
        
        # F7: Announcement
        self.announcement_enabled = announcement_enabled
        self.announcement_file = announcement_file
        
        # F8: DTMF Door Opener
        self.dtmf_enabled = dtmf_enabled
        self.dtmf_door_code = dtmf_door_code
        self.dtmf_light_code = dtmf_light_code
        
        # F12: Doorbell Buttons
        self.doorbell_buttons = doorbell_buttons or []
        
        # Connections
        self._siedle_conn: Optional[SipConnection] = None
        self._external_conn: Optional[SipConnection] = None
        
        # Active calls
        self._siedle_call: Optional[SipCall] = None
        self._external_call: Optional[SipCall] = None
        
        # State
        self._state = CallState.IDLE
        self._running = False
        
        # Callbacks (support multiple callbacks per event)
        self._on_doorbell_callbacks: List[Callable[[dict], None]] = []
        self._on_call_state_change_callbacks: List[Callable[[CallState, dict], None]] = []
        self._on_incoming_external_callbacks: List[Callable[[dict], None]] = []
        self._on_dtmf_action_callbacks: List[Callable[[str, str], None]] = []  # (action, code)
        
        # RTP Bridge (will be set externally)
        self.rtp_bridge: Optional[Any] = None
        
        # Siedle API reference (for DTMF door opener)
        self.siedle_api: Optional[Any] = None
        
        # Recording
        self._recording_task: Optional[asyncio.Task] = None
        self._current_recording_file: Optional[str] = None
        
        # F2: Current forwarding target index (for sequential forwarding)
        self._forward_target_index: int = 0
    
    @property
    def state(self) -> CallState:
        return self._state
    
    @property
    def is_call_active(self) -> bool:
        return self._state in (CallState.CONNECTED, CallState.RECORDING, CallState.RINGING_IN, CallState.RINGING_OUT)
    
    def set_on_doorbell(self, callback: Callable[[dict], None]):
        """Add doorbell callback."""
        if callback not in self._on_doorbell_callbacks:
            self._on_doorbell_callbacks.append(callback)
    
    def set_on_call_state_change(self, callback: Callable[[CallState, dict], None]):
        """Add call state change callback."""
        if callback not in self._on_call_state_change_callbacks:
            self._on_call_state_change_callbacks.append(callback)
    
    def set_on_incoming_external(self, callback: Callable[[dict], None]):
        """Add incoming external call callback."""
        if callback not in self._on_incoming_external_callbacks:
            self._on_incoming_external_callbacks.append(callback)
    
    def set_on_dtmf_action(self, callback: Callable[[str, str], None]):
        """Register callback for DTMF actions (action_type, code)."""
        if callback not in self._on_dtmf_action_callbacks:
            self._on_dtmf_action_callbacks.append(callback)
    
    def _is_in_forward_window(self) -> bool:
        """Check if current time is within the forwarding schedule (F6).
        
        Returns True if forwarding should be active right now.
        Always returns True if schedule is disabled.
        """
        if not self.forward_schedule_enabled:
            return True
        
        from datetime import datetime as dt
        now = dt.now()
        
        # Check day of week (0=Monday, 6=Sunday)
        if now.weekday() not in self.forward_schedule_days:
            _LOGGER.info(f"Forward schedule: day {now.weekday()} not in {self.forward_schedule_days}")
            return False
        
        # Parse start/end times
        try:
            start_h, start_m = map(int, self.forward_schedule_start.split(":"))
            end_h, end_m = map(int, self.forward_schedule_end.split(":"))
        except ValueError:
            _LOGGER.warning(f"Invalid schedule times: {self.forward_schedule_start} - {self.forward_schedule_end}")
            return True
        
        now_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        
        # Handle midnight crossing (e.g. 23:00 - 02:00)
        if start_minutes <= end_minutes:
            in_window = start_minutes <= now_minutes <= end_minutes
        else:
            # Midnight wrap: in window if AFTER start OR BEFORE end
            in_window = now_minutes >= start_minutes or now_minutes <= end_minutes
        
        if not in_window:
            _LOGGER.info(f"Forward schedule: {now.strftime('%H:%M')} outside {self.forward_schedule_start}-{self.forward_schedule_end}")
        
        return in_window
    
    def _get_forward_targets(self) -> List[str]:
        """Get list of forwarding targets (F2).
        
        Supports comma-separated numbers in forward_to_number.
        Returns list of SIP numbers to try sequentially.
        """
        if not self.forward_to_number:
            return []
        return [n.strip() for n in self.forward_to_number.split(",") if n.strip()]
    
    def _start_forward_timeout(self):
        """Start forward timeout timer (F1).
        
        If external phone doesn't answer within timeout seconds,
        cancel the call and try next target or fall back.
        """
        if self.forward_timeout <= 0:
            return
        
        self._cancel_forward_timeout()
        
        def _on_timeout():
            _LOGGER.warning(f"Forward timeout ({self.forward_timeout}s) — external phone didn't answer")
            
            targets = self._get_forward_targets()
            next_index = self._forward_target_index + 1
            
            if next_index < len(targets):
                # F2: Try next target
                _LOGGER.info(f"Trying next target [{next_index}]: {targets[next_index]}")
                
                # Send CANCEL to current external call
                if self._external_call and self._external_conn:
                    try:
                        cancel_msg = self._build_cancel_for_invite()
                        if cancel_msg:
                            self._external_conn.send(cancel_msg)
                            _LOGGER.info("CANCEL sent to current external target")
                    except Exception as e:
                        _LOGGER.warning(f"Failed to CANCEL external: {e}")
                
                self._external_call = None
                self._forward_target_index = next_index
                
                # Forward to next target
                self._forward_to_external_target(targets[next_index])
            else:
                # No more targets — fall back to recording or end call
                _LOGGER.info("All forward targets exhausted")
                if self.auto_answer and self._siedle_call:
                    _LOGGER.info("Falling back to recording-only mode")
                    self._answer_siedle_call()
                else:
                    self._end_call()
        
        self._forward_timeout_timer = threading.Timer(self.forward_timeout, _on_timeout)
        self._forward_timeout_timer.daemon = True
        self._forward_timeout_timer.start()
        _LOGGER.info(f"Forward timeout started: {self.forward_timeout}s")
    
    def _cancel_forward_timeout(self):
        """Cancel any active forward timeout timer."""
        if self._forward_timeout_timer:
            self._forward_timeout_timer.cancel()
            self._forward_timeout_timer = None
    
    def _build_cancel_for_invite(self) -> Optional[bytes]:
        """Build a CANCEL request for the current external INVITE."""
        if not self._external_call or not self._external_conn:
            return None
        
        local_ip = self._external_conn._get_local_ip()
        local_port = self._external_conn.config.port
        transport_str = "TLS" if self._external_conn.config.transport == SipTransport.TLS else "UDP"
        branch = uuid.uuid4().hex[:12]
        
        targets = self._get_forward_targets()
        target_idx = min(self._forward_target_index, len(targets) - 1) if targets else 0
        to_uri = self._external_call.to_uri or (
            f"sip:{targets[target_idx]}@{self.external_config.host}" if targets else ""
        )
        
        cancel = (
            f"CANCEL {to_uri} SIP/2.0\r\n"
            f"Via: SIP/2.0/{transport_str} {local_ip}:{local_port};branch=z9hG4bK{branch}\r\n"
            f"From: {self._external_call.from_uri}\r\n"
            f"To: {self._external_call.to_uri}\r\n"
            f"Call-ID: {self._external_call.call_id}\r\n"
            f"CSeq: 1 CANCEL\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        return cancel.encode('utf-8')
    
    def _setup_dtmf_detection(self):
        """Set up DTMF detection on the RTP bridge (F8)."""
        if not self.dtmf_enabled or not self.rtp_bridge:
            return
        
        def on_dtmf_digit(digit: str):
            """Handle individual DTMF digit."""
            _LOGGER.info(f"DTMF digit from phone: '{digit}'")
            
            # Check for single-character door opener code
            if len(self.dtmf_door_code) == 1 and digit == self.dtmf_door_code:
                _LOGGER.info(f"🔓 DTMF door opener triggered! Code: '{digit}'")
                self._execute_dtmf_action("open_door", digit)
            
            # Check for single-character light code
            if len(self.dtmf_light_code) == 1 and digit == self.dtmf_light_code:
                _LOGGER.info(f"💡 DTMF light toggle triggered! Code: '{digit}'")
                self._execute_dtmf_action("toggle_light", digit)
        
        def on_dtmf_code(code: str):
            """Handle completed DTMF code sequence."""
            _LOGGER.info(f"DTMF code sequence: '{code}'")
            
            # Check multi-digit codes
            if len(self.dtmf_door_code) > 1 and code.endswith(self.dtmf_door_code):
                _LOGGER.info(f"🔓 DTMF door opener (multi-digit): '{code}'")
                self._execute_dtmf_action("open_door", code)
            elif len(self.dtmf_light_code) > 1 and code.endswith(self.dtmf_light_code):
                _LOGGER.info(f"💡 DTMF light toggle (multi-digit): '{code}'")
                self._execute_dtmf_action("toggle_light", code)
        
        self.rtp_bridge.set_dtmf_callbacks(
            on_digit=on_dtmf_digit,
            on_code=on_dtmf_code,
            code_timeout=3.0,
        )
        _LOGGER.info(f"DTMF detection configured: door='{self.dtmf_door_code}', light='{self.dtmf_light_code}'")
    
    def _execute_dtmf_action(self, action: str, code: str):
        """Execute a DTMF-triggered action (F8)."""
        if action == "open_door" and self.siedle_api:
            try:
                self.siedle_api.openDoor()
                _LOGGER.info("Door opened via DTMF!")
            except Exception as e:
                _LOGGER.error(f"DTMF door open failed: {e}")
        elif action == "toggle_light" and self.siedle_api:
            try:
                self.siedle_api.turnOnLight()
                _LOGGER.info("Light toggled via DTMF!")
            except Exception as e:
                _LOGGER.error(f"DTMF light toggle failed: {e}")
        
        # Notify callbacks
        for callback in self._on_dtmf_action_callbacks:
            try:
                callback(action, code)
            except Exception as e:
                _LOGGER.error(f"DTMF action callback error: {e}")
    
    def _identify_doorbell_button(self, caller_id: str, from_header: str) -> Optional[str]:
        """Identify which doorbell button was pressed (F12).
        
        Matches caller_id against configured doorbell button patterns.
        Returns the button name or None.
        """
        if not self.doorbell_buttons:
            return None
        
        for button in self.doorbell_buttons:
            pattern = button.get("pattern", "")
            name = button.get("name", "")
            if pattern and pattern in caller_id:
                _LOGGER.info(f"Doorbell button identified: '{name}' (pattern '{pattern}' matched '{caller_id}')")
                return name
            if pattern and pattern in (from_header or ""):
                _LOGGER.info(f"Doorbell button identified: '{name}' (pattern '{pattern}' in From header)")
                return name
        
        return None
    
    def _set_state(self, new_state: CallState, data: Optional[dict] = None):
        """Update call state and notify."""
        old_state = self._state
        self._state = new_state
        _LOGGER.info(f"SIP Call State: {old_state.value} -> {new_state.value}")
        
        # Notify all registered callbacks
        for callback in self._on_call_state_change_callbacks:
            try:
                callback(new_state, data or {})
            except Exception as e:
                _LOGGER.error(f"Call state callback error: {e}")
    
    def _handle_siedle_message(self, msg: SipMessage):
        """Handle message from Siedle SIP server."""
        _LOGGER.debug(f"Siedle message: method={msg.method}, status={msg.status_code}, from={msg.from_header}")
        
        if msg.is_request and msg.method == "INVITE":
            _LOGGER.warning(f"🔔 SIEDLE INVITE - DOORBELL! From: {msg.from_header}")
            
            # Guard: If there's already an active call, clean it up first
            if self._siedle_call or self._state != CallState.IDLE:
                _LOGGER.warning(f"⚠️ New INVITE while previous call active! state={self._state.value}, "
                              f"siedle_call={'yes (call_id=' + self._siedle_call.call_id + ')' if self._siedle_call else 'no'}, "
                              f"external_call={'yes' if self._external_call else 'no'}")
                _LOGGER.warning("Cleaning up previous call before processing new INVITE...")
                self._end_call()
            
            # Log ALL headers for diagnostics (especially Via, Record-Route)
            _LOGGER.info(f"INVITE has {len(msg.via_list)} Via header(s):")
            for i, via in enumerate(msg.via_list):
                _LOGGER.info(f"  Via[{i}]: {via}")
            if msg.record_route_list:
                _LOGGER.info(f"INVITE has {len(msg.record_route_list)} Record-Route header(s):")
                for i, rr in enumerate(msg.record_route_list):
                    _LOGGER.info(f"  Record-Route[{i}]: {rr}")
            _LOGGER.debug(f"INVITE all headers: {msg.header_list}")
            
            # Send 100 Trying IMMEDIATELY to prevent retransmissions/timeout
            try:
                trying = self._siedle_conn.create_response(msg, 100, "Trying")
                self._siedle_conn.send(trying)
                _LOGGER.info("Sent 100 Trying to Siedle")
            except Exception as e:
                _LOGGER.error(f"Failed to send 100 Trying: {e}")
            
            # Extract caller info
            from_match = re.search(r'<sip:([^@>]+)@([^>]+)>', msg.from_header or "")
            caller_id = from_match.group(1) if from_match else "unknown"
            caller_host = from_match.group(2) if from_match else "unknown"
            
            data = {
                "source": "siedle",
                "from": msg.from_header,
                "call_id": msg.call_id,
                "caller_id": caller_id,
                "caller_host": caller_host,
                "sdp": msg.body,
            }
            
            # F12: Identify doorbell button
            button_name = self._identify_doorbell_button(caller_id, msg.from_header)
            if button_name:
                data["button_name"] = button_name
            
            _LOGGER.info(f"Doorbell data: caller_id={caller_id}, call_id={msg.call_id}, button={button_name or 'default'}")
            
            # Notify all doorbell callbacks
            if self._on_doorbell_callbacks:
                for callback in self._on_doorbell_callbacks:
                    try:
                        _LOGGER.debug("Calling doorbell callback...")
                        callback(data)
                        _LOGGER.debug("Doorbell callback completed")
                    except Exception as e:
                        _LOGGER.error(f"Doorbell callback error: {e}")
                        _LOGGER.exception(e)
            else:
                _LOGGER.warning("No doorbell callbacks registered!")
            
            # Store call info for forwarding
            self._siedle_call = SipCall(
                call_id=msg.call_id,
                from_uri=msg.from_header,
                to_uri=msg.to_header,
                from_tag=self._extract_tag(msg.from_header),
                state=CallState.RINGING_IN,
                remote_rtp_host=msg.get_sdp_connection_ip(),
                remote_rtp_port=msg.get_sdp_media_port() or 0,
                invite_data=msg.raw.encode('utf-8'),
            )
            
            self._set_state(CallState.RINGING_IN, data)
            
            # Reset sequential forwarding index
            self._forward_target_index = 0
            
            # If forwarding enabled and external server connected
            # F6: Check schedule before forwarding
            if (self.forward_to_number and self._external_conn and 
                self._external_conn.registered and self._is_in_forward_window()):
                self._forward_to_external()
            elif self.auto_answer:
                if not self._is_in_forward_window():
                    _LOGGER.info("Forward schedule inactive — answering locally")
                self._answer_siedle_call()
        
        elif msg.is_request and msg.method == "BYE":
            _LOGGER.info("Siedle: BYE received - call ended")
            self._send_ok_response(self._siedle_conn, msg)
            self._end_call()
        
        elif msg.is_request and msg.method == "CANCEL":
            _LOGGER.info("Siedle: CANCEL received — caller hung up before answer")
            self._send_ok_response(self._siedle_conn, msg)
            
            # Also send 487 Request Terminated for the original INVITE
            if self._siedle_call and self._siedle_call.invite_data:
                try:
                    original = SipConnection.parse_message(self._siedle_call.invite_data)
                    response = self._siedle_conn.create_response(original, 487, "Request Terminated")
                    self._siedle_conn.send(response)
                    _LOGGER.info("487 Request Terminated sent to Siedle")
                except Exception as e:
                    _LOGGER.warning(f"Failed to send 487: {e}")
            
            # Full cleanup — cancel external call too if in progress
            self._end_call()
        
        elif msg.is_request and msg.method == "ACK":
            _LOGGER.info("Siedle: ACK received - call fully established, RTP should now flow")
            # ACK doesn't require a response
        
        elif not msg.is_request:
            # Log all SIP responses (100, 180, 183, etc.)
            _LOGGER.debug(f"Siedle: SIP response {msg.status_code} {msg.status_text}")
    
    def _handle_external_message(self, msg: SipMessage):
        """Handle message from external SIP server."""
        if msg.is_request and msg.method == "INVITE":
            _LOGGER.info(f"External INVITE from: {msg.from_header}")
            
            # Check if from allowed number
            if self.forward_from_number:
                if self.forward_from_number not in (msg.from_header or ""):
                    _LOGGER.warning(f"Rejecting call from unauthorized number: {msg.from_header}")
                    response = self._external_conn.create_response(msg, 403, "Forbidden")
                    self._external_conn.send(response)
                    return
            
            # Notify all incoming external callbacks
            if self._on_incoming_external_callbacks:
                for callback in self._on_incoming_external_callbacks:
                    try:
                        callback({
                            "from": msg.from_header,
                            "call_id": msg.call_id,
                        })
                    except Exception as e:
                        _LOGGER.error(f"Incoming external callback error: {e}")
            
            # Store call info
            self._external_call = SipCall(
                call_id=msg.call_id,
                from_uri=msg.from_header,
                to_uri=msg.to_header,
                from_tag=self._extract_tag(msg.from_header),
                state=CallState.RINGING_IN,
                remote_rtp_host=msg.get_sdp_connection_ip(),
                remote_rtp_port=msg.get_sdp_media_port() or 0,
                invite_data=msg.raw.encode('utf-8'),
            )
            
            # TODO: Forward incoming external calls to Siedle door station
            self._set_state(CallState.RINGING_IN, {"source": "external", "from": msg.from_header})
        
        elif not msg.is_request:
            # Response to OUR outbound INVITE (doorbell → phone forwarding)
            if msg.status_code == 100:
                _LOGGER.info("External: 100 Trying")
            
            elif msg.status_code == 180 or msg.status_code == 183:
                _LOGGER.info("External: Ringing...")
                # TODO: Optionally send 180 Ringing upstream to Siedle
            
            elif msg.status_code == 200:
                _LOGGER.info("External: 200 OK — Phone picked up!")
                
                # F1: Cancel forward timeout — phone answered
                self._cancel_forward_timeout()
                
                if self._external_call:
                    self._external_call.to_tag = self._extract_tag(msg.to_header)
                    self._external_call.state = CallState.CONNECTED
                    self._external_call.remote_rtp_port = msg.get_sdp_media_port() or 0
                    self._external_call.remote_rtp_host = msg.get_sdp_connection_ip()
                    
                    _LOGGER.info(f"External RTP endpoint: {self._external_call.remote_rtp_host}:{self._external_call.remote_rtp_port}")
                    
                    # Send ACK to external
                    ack = self._external_conn.create_ack(self._external_call, msg)
                    self._external_conn.send(ack)
                    _LOGGER.info("ACK sent to external")
                    
                    # Now answer Siedle with bridging
                    self._answer_siedle_and_bridge()
                    self._set_state(CallState.CONNECTED, {
                        "external_host": self._external_call.remote_rtp_host,
                        "external_port": self._external_call.remote_rtp_port,
                    })
            
            elif msg.status_code in (401, 407):
                # 401 Unauthorized or 407 Proxy Auth Required — retry INVITE with credentials
                # Safety: only process if there's an active external call (INVITE in progress)
                if not self._external_call or self._state == CallState.IDLE:
                    _LOGGER.debug(f"External: {msg.status_code} response ignored (no active call)")
                    return
                is_proxy = (msg.status_code == 407)
                auth_header_name = "Proxy-Authenticate" if is_proxy else "WWW-Authenticate"
                auth_value = msg.headers.get(auth_header_name, "")
                if not auth_value:
                    # Try both headers as fallback
                    auth_value = msg.headers.get("WWW-Authenticate") or msg.headers.get("Proxy-Authenticate", "")
                _LOGGER.info(f"External: {msg.status_code} {'Proxy Auth Required' if is_proxy else 'Unauthorized'} — retrying with credentials")
                realm_match = re.search(r'realm="([^"]+)"', auth_value)
                nonce_match = re.search(r'nonce="([^"]+)"', auth_value)
                
                if realm_match and nonce_match and self._external_call:
                    self._external_conn._realm = realm_match.group(1)
                    self._external_conn._nonce = nonce_match.group(1)
                    
                    # F2: Use current target from list
                    targets = self._get_forward_targets()
                    current_target = targets[self._forward_target_index] if targets else self.forward_to_number
                    to_uri = f"sip:{current_target}@{self.external_config.host}"
                    response_digest = self._external_conn._compute_digest("INVITE", to_uri)
                    
                    # Rebuild the INVITE with Proxy-Authorization
                    # Reuse the same SDP from the original INVITE
                    local_ip = self._external_conn._get_local_ip()
                    branch = uuid.uuid4().hex[:12]
                    transport_str = "TLS" if self._external_conn.config.transport == SipTransport.TLS else "UDP"
                    
                    # We need the SDP — reconstruct from rtp_bridge
                    sdp_ip_b = local_ip
                    sdp_port_b = self.rtp_bridge.local_port_b if self.rtp_bridge else 20000
                    
                    session_id = str(int(time.time()))
                    ext_sdp = (
                        f"v=0\r\n"
                        f"o=- {session_id} {session_id} IN IP4 {sdp_ip_b}\r\n"
                        f"s=Siedle Doorbell\r\n"
                        f"c=IN IP4 {sdp_ip_b}\r\n"
                        f"t=0 0\r\n"
                        f"m=audio {sdp_port_b} RTP/AVP 8 0 101\r\n"
                        f"a=rtpmap:8 PCMA/8000\r\n"
                        f"a=rtpmap:0 PCMU/8000\r\n"
                        f"a=rtpmap:101 telephone-event/8000\r\n"
                        f"a=fmtp:101 0-16\r\n"
                        f"a=ptime:20\r\n"
                        f"a=sendrecv\r\n"
                    )
                    
                    # Send ACK for the 401/407 first (required by SIP)
                    ack = self._external_conn.create_ack(self._external_call, msg)
                    self._external_conn.send(ack)
                    
                    # Resend INVITE with auth
                    invite_msg, call = self._external_conn.create_invite(
                        to_uri, sdp_port_b, call_id=self._external_call.call_id,
                        sdp_override=ext_sdp
                    )
                    
                    # Inject Authorization or Proxy-Authorization header
                    auth_prefix = "Proxy-Authorization" if is_proxy else "Authorization"
                    invite_str = invite_msg.decode('utf-8')
                    auth_header = (
                        f'{auth_prefix}: Digest username="{self._external_conn.config.username}", '
                        f'realm="{self._external_conn._realm}", '
                        f'nonce="{self._external_conn._nonce}", '
                        f'uri="{to_uri}", '
                        f'response="{response_digest}", '
                        f'algorithm=MD5'
                    )
                    # Insert before Content-Type
                    invite_str = invite_str.replace(
                        "Content-Type: application/sdp",
                        f"{auth_header}\r\nContent-Type: application/sdp"
                    )
                    
                    self._external_call = call
                    self._external_conn.send(invite_str.encode('utf-8'))
                    _LOGGER.info(f"Resent INVITE with {auth_prefix}")
                else:
                    if not realm_match or not nonce_match:
                        _LOGGER.error(f"Cannot handle {msg.status_code}: missing realm/nonce in: {auth_value}")
                    else:
                        _LOGGER.error(f"Cannot handle {msg.status_code}: no active external call")
                    self._set_state(CallState.IDLE)
            
            elif msg.status_code >= 400:
                _LOGGER.warning(f"External: Call rejected: {msg.status_code} {msg.status_text}")
                # Forwarding failed — fall back to recording-only if auto_answer
                if self.auto_answer and self._siedle_call:
                    _LOGGER.info("Forwarding failed, falling back to recording-only mode")
                    self._answer_siedle_call()
                else:
                    # Full cleanup — not just state reset
                    _LOGGER.info("Forwarding failed, no fallback — cleaning up")
                    self._end_call()
        
        elif msg.is_request and msg.method == "BYE":
            _LOGGER.info("External: BYE received — phone hung up")
            self._send_ok_response(self._external_conn, msg)
            # Propagate: also hang up Siedle side
            _LOGGER.info("Propagating hangup to Siedle side...")
            self._end_call()
    
    def _extract_tag(self, header: Optional[str]) -> Optional[str]:
        """Extract tag from SIP header."""
        if not header:
            return None
        match = re.search(r'tag=([^;>\s]+)', header)
        return match.group(1) if match else None
    
    def _send_ok_response(self, conn: SipConnection, request: SipMessage):
        """Send 200 OK response."""
        response = conn.create_response(request, 200, "OK")
        conn.send(response)
    
    def _forward_to_external(self):
        """Forward incoming Siedle call to external SIP server (B2BUA late-answer).
        
        Flow:
        1. Siedle INVITE already received and stored in self._siedle_call
        2. We set up the RTP bridge (allocate sockets, STUN for Siedle side)
        3. We send INVITE to external SIP with socket_b's port in SDP
        4. We wait for external to answer (200 OK)
        5. Only then do we answer Siedle (in _handle_external_message)
        
        F2: Supports comma-separated targets — starts with first target.
        F1: Starts timeout timer for each target.
        """
        if not self._external_conn or not self._external_conn.registered:
            _LOGGER.warning("Cannot forward: External SIP not connected — falling back to recording only")
            if self.auto_answer:
                self._answer_siedle_call()
            return
        
        # F2: Get target list
        targets = self._get_forward_targets()
        if not targets:
            _LOGGER.warning("Cannot forward: No forward_to_number configured")
            return
        
        if not self.rtp_bridge:
            _LOGGER.error("Cannot forward: No RTP bridge available")
            return
        
        target = targets[self._forward_target_index]
        _LOGGER.info(f"Forwarding doorbell to {target} [{self._forward_target_index+1}/{len(targets)}] via {self.external_config.host}...")
        _LOGGER.info(f"  State: {self._state.value}, RTP bridge running: {self.rtp_bridge._running if self.rtp_bridge else 'N/A'}")
        
        # Step 1: Set up RTP bridge — allocate both sockets
        remote_siedle = (
            self._siedle_call.remote_rtp_host,
            self._siedle_call.remote_rtp_port
        )
        local_rtp_port_a, local_rtp_port_b = self.rtp_bridge.setup(
            remote_a=remote_siedle,
            remote_b=None  # Not known until external 200 OK
        )
        
        # Step 2: STUN on socket_a to discover Siedle-facing external port
        stun_ip_a, stun_port_a = self.rtp_bridge.stun_discover_external_port()
        if stun_port_a:
            _LOGGER.info(f"STUN (Siedle): external {stun_ip_a}:{stun_port_a} for local port {local_rtp_port_a}")
        
        # Store STUN results for later use when answering Siedle
        self._stun_siedle_ip = stun_ip_a
        self._stun_siedle_port = stun_port_a
        
        # Step 3: Determine external-facing IP for socket_b
        ext_host = self.external_config.host
        sdp_ip_b = self._external_conn._get_local_ip()
        sdp_port_b = local_rtp_port_b
        
        if not _is_private_ip(ext_host):
            stun_ip_b, stun_port_b = self.rtp_bridge.stun_discover_external_port_b()
            if stun_ip_b and stun_port_b:
                sdp_ip_b = stun_ip_b
                sdp_port_b = stun_port_b
                _LOGGER.info(f"STUN (External): external {sdp_ip_b}:{sdp_port_b} for local port {local_rtp_port_b}")
        else:
            _LOGGER.info(f"External SIP is on LAN ({ext_host}) — using local IP {sdp_ip_b} in SDP")
        
        # Store for reuse on sequential targets
        self._cached_sdp_ip_b = sdp_ip_b
        self._cached_sdp_port_b = sdp_port_b
        self._cached_local_rtp_port_b = local_rtp_port_b
        
        # Send INVITE to first target
        self._forward_to_external_target(target)
    
    def _forward_to_external_target(self, target_number: str):
        """Send INVITE to a specific external target (supports F2 sequential forwarding)."""
        sdp_ip_b = getattr(self, '_cached_sdp_ip_b', self._external_conn._get_local_ip())
        sdp_port_b = getattr(self, '_cached_sdp_port_b', 20000)
        local_rtp_port_b = getattr(self, '_cached_local_rtp_port_b', 20000)
        
        # Build SDP for external INVITE
        session_id = str(int(time.time()))
        ext_sdp = (
            f"v=0\r\n"
            f"o=- {session_id} {session_id} IN IP4 {sdp_ip_b}\r\n"
            f"s=Siedle Doorbell\r\n"
            f"c=IN IP4 {sdp_ip_b}\r\n"
            f"t=0 0\r\n"
            f"m=audio {sdp_port_b} RTP/AVP 8 0 101\r\n"
            f"a=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:0 PCMU/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\n"
            f"a=fmtp:101 0-16\r\n"
            f"a=ptime:20\r\n"
            f"a=sendrecv\r\n"
        )
        
        # Send INVITE to target
        to_uri = f"sip:{target_number}@{self.external_config.host}"
        invite_msg, call = self._external_conn.create_invite(
            to_uri, local_rtp_port_b, sdp_override=ext_sdp
        )
        self._external_call = call
        self._external_conn.send(invite_msg)
        
        self._set_state(CallState.RINGING_OUT, {"target": target_number})
        _LOGGER.info(f"INVITE sent to external: {to_uri} (RTP {sdp_ip_b}:{sdp_port_b})")
        
        # F1: Start forward timeout
        self._start_forward_timeout()
    
    def _answer_siedle_call(self):
        """Send 200 OK to Siedle INVITE."""
        if not self._siedle_call or not self._siedle_conn:
            return
        
        local_ip = self._siedle_conn._get_local_ip()
        
        # Use external IP for SDP if behind NAT (like PJSIP's contactRewriteUse)
        sdp_ip = self._siedle_conn.get_sdp_ip()
        if sdp_ip != local_ip:
            _LOGGER.info(f"NAT traversal: Using external IP {sdp_ip} in SDP instead of local {local_ip}")
        
        # Parse original INVITE to extract SRTP info
        srtp_crypto = None
        uses_srtp = False
        crypto_line = None
        
        if self._siedle_call.invite_data:
            invite_msg = SipConnection.parse_message(self._siedle_call.invite_data)
            if invite_msg.body:
                # Check for SRTP
                if "RTP/SAVP" in invite_msg.body:
                    uses_srtp = True
                    _LOGGER.info("Siedle uses SRTP - extracting crypto parameters")
                    
                    # Extract crypto line from SDP
                    for line in invite_msg.body.split('\r\n'):
                        if line.startswith('a=crypto:'):
                            crypto_line = line[9:]  # Remove "a=crypto:" prefix
                            _LOGGER.info(f"Found crypto line: {crypto_line[:50]}...")
                            break
                    
                    if crypto_line:
                        try:
                            from .srtp_handler import SRTPCrypto
                            srtp_crypto = SRTPCrypto.from_base64(crypto_line)
                            if srtp_crypto:
                                _LOGGER.info("✓ SRTP crypto initialized successfully")
                            else:
                                _LOGGER.error("Failed to initialize SRTP crypto")
                        except ImportError as e:
                            _LOGGER.error(f"SRTP not available - install 'cryptography' package: {e}")
                        except Exception as e:
                            _LOGGER.error(f"Failed to parse SRTP crypto: {e}")
        
        # Setup RTP Bridge if available
        if self.rtp_bridge:
            _LOGGER.info(f"Setting up RTP Bridge for recording/forwarding...")
            remote_siedle = (
                self._siedle_call.remote_rtp_host,
                self._siedle_call.remote_rtp_port
            )
            
            # Setup RTP bridge (returns local ports)
            local_rtp_port, _ = self.rtp_bridge.setup(
                remote_a=remote_siedle,
                remote_b=None  # No forwarding to external for now
            )
            
            # Discover actual NAT-mapped external port using STUN from the RTP socket
            # This sends a STUN Binding Request from the same socket that will receive RTP,
            # so we get the exact external port the NAT assigned to this socket.
            stun_ip, stun_port = self.rtp_bridge.stun_discover_external_port()
            if stun_port:
                rtp_external_port = stun_port
                _LOGGER.info(f"NAT: STUN discovered external RTP port {stun_port} for local port {local_rtp_port}")
                # Also update sdp_ip if STUN gave us a different IP
                if stun_ip and stun_ip != sdp_ip:
                    _LOGGER.info(f"NAT: STUN IP {stun_ip} differs from Via IP {sdp_ip}, using STUN IP")
                    sdp_ip = stun_ip
            else:
                rtp_external_port = local_rtp_port
                _LOGGER.warning(f"NAT: STUN failed, falling back to 1:1 port mapping assumption: {local_rtp_port}")
            
            # Set SRTP crypto if available
            if srtp_crypto:
                self.rtp_bridge.set_srtp_crypto(srtp_crypto)
            
            # Register callback to auto-hangup when recording stops
            def on_recording_stopped():
                _LOGGER.info("Recording finished - auto-hanging up call")
                # Schedule hangup in a separate thread to avoid deadlocks
                threading.Thread(target=self._end_call, daemon=True).start()
            self.rtp_bridge.set_on_recording_stopped(on_recording_stopped)
            
            # Start RTP bridge BEFORE sending 200 OK
            self.rtp_bridge.start()
            
            # Send NAT punch-through packets to open NAT for incoming RTP
            # Must be sent BEFORE 200 OK so the firewall pinhole is ready
            if remote_siedle[0] and remote_siedle[1]:
                self.rtp_bridge.send_nat_punch(remote_siedle, count=5)
            
            _LOGGER.info(f"RTP Bridge started on local port {local_rtp_port}, external port {rtp_external_port}, remote Siedle: {remote_siedle}")
            
            # Use external port in SDP
            sdp_rtp_port = rtp_external_port
        else:
            # Fallback to hardcoded port if no RTP bridge
            local_rtp_port = 20002
            sdp_rtp_port = local_rtp_port
            _LOGGER.warning("No RTP Bridge available - using hardcoded port")
        
        # Build SDP response with external IP for NAT traversal
        # Like PJSIP, we advertise our public (external) IP so Siedle server can reach us
        
        if uses_srtp and crypto_line:
            media_proto = "RTP/SAVP"
            # RFC 4568: Answer MUST contain its own crypto key, NOT echo the offerer's key
            try:
                from .srtp_handler import SRTPCrypto
                our_crypto_line, _ = SRTPCrypto.generate_sdp_crypto_line()
                crypto_attr = f"a=crypto:{our_crypto_line}\r\n"
                _LOGGER.info(f"Responding with RTP/SAVP, own SRTP key generated")
                _LOGGER.debug(f"Our crypto line: {our_crypto_line[:50]}...")
            except Exception as e:
                _LOGGER.error(f"Failed to generate SRTP key, using offerer's: {e}")
                crypto_attr = f"a=crypto:{crypto_line}\r\n"
        else:
            media_proto = "RTP/AVP"
            crypto_attr = ""
        
        sdp = (
            f"v=0\r\n"
            f"o=- {int(time.time())} {int(time.time())} IN IP4 {sdp_ip}\r\n"
            f"s=Siedle HA\r\n"
            f"c=IN IP4 {sdp_ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio {sdp_rtp_port} {media_proto} 8 101\r\n"
            f"a=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\n"
            f"a=fmtp:101 0-16\r\n"
            f"a=ptime:20\r\n"
            f"{crypto_attr}"
            f"a=sendrecv\r\n"
        )
        
        _LOGGER.info(f"SDP for 200 OK: sdp_ip={sdp_ip}, rtp_port={sdp_rtp_port}, proto={media_proto}, srtp={'enabled' if srtp_crypto else 'disabled'}")
        if sdp_ip != local_ip:
            _LOGGER.info(f"NAT: SDP uses external IP {sdp_ip} (local={local_ip}), external RTP port {sdp_rtp_port} (local={local_rtp_port})")
        _LOGGER.debug(f"SDP body:\n{sdp}")
        
        # Parse original INVITE to create proper response
        if self._siedle_call.invite_data:
            original = SipConnection.parse_message(self._siedle_call.invite_data)
            response = self._siedle_conn.create_response(original, 200, "OK", sdp, local_rtp_port)
            
            # Log the full raw 200 OK for diagnostics
            _LOGGER.debug(f"Raw 200 OK:\n{response.decode('utf-8', errors='replace')}")
            
            # Log our own Via and Contact to debug NAT issues
            response_msg = SipConnection.parse_message(response)
            _LOGGER.info(f"200 OK Via count: {len(response_msg.via_list)}")
            for i, via in enumerate(response_msg.via_list):
                _LOGGER.info(f"  200 OK Via[{i}]: {via}")
            _LOGGER.info(f"Our Contact: {response_msg.contact}")
            
            self._siedle_conn.send(response)
            _LOGGER.info("200 OK sent to Siedle")
            
            # Send additional NAT punch-through AFTER 200 OK
            # Siedle starts sending RTP after processing our 200 OK
            if self.rtp_bridge and self._siedle_call.remote_rtp_host and self._siedle_call.remote_rtp_port:
                post_remote = (self._siedle_call.remote_rtp_host, self._siedle_call.remote_rtp_port)
                self.rtp_bridge.send_nat_punch(post_remote, count=3)
            
            self._siedle_call.state = CallState.CONNECTED
            self._siedle_call.local_rtp_port = local_rtp_port
            
            # Start recording if enabled
            if self.recording_enabled and self.rtp_bridge and self.recording_path:
                try:
                    _LOGGER.info(f"Starting automatic recording: {self.recording_path}")
                    self._current_recording_file = self.rtp_bridge.start_recording(
                        self.recording_path,
                        duration=self.recording_duration
                    )
                    _LOGGER.info(f"Recording started: {self._current_recording_file}")
                except Exception as e:
                    _LOGGER.error(f"Failed to start recording: {e}")
            
            # Notify state change with recording info
            state_data = {
                "rtp_port": local_rtp_port,
            }
            if self._current_recording_file:
                state_data["recording_file"] = self._current_recording_file
            
            self._set_state(CallState.CONNECTED, state_data)
            _LOGGER.info(f"Siedle call answered - RTP port {local_rtp_port}")
    
    def _answer_siedle_and_bridge(self):
        """Answer Siedle INVITE and set up bidirectional audio bridge to external phone.
        
        Called when external phone picks up (200 OK). This:
        1. Parses Siedle's SRTP offer and creates decrypt context
        2. Generates our SRTP answer key and creates encrypt context
        3. Configures rtp_bridge with both SRTP contexts
        4. Sets external phone as remote_b
        5. Sends 200 OK to Siedle
        6. Starts bidirectional bridge (A↔B)
        """
        if not self._siedle_call or not self._siedle_conn:
            _LOGGER.error("Cannot answer Siedle: no pending call")
            return
        if not self._external_call:
            _LOGGER.error("Cannot bridge: no external call")
            return
        if not self.rtp_bridge:
            _LOGGER.error("Cannot bridge: no RTP bridge")
            return
        
        _LOGGER.info("=== Answering Siedle + Setting up Bridge ===")
        
        local_ip = self._siedle_conn._get_local_ip()
        
        # --- SRTP setup ---
        srtp_decrypt = None  # For Siedle→us decryption
        srtp_encrypt = None  # For us→Siedle encryption
        uses_srtp = False
        crypto_line = None
        our_crypto_line = None
        
        if self._siedle_call.invite_data:
            invite_msg = SipConnection.parse_message(self._siedle_call.invite_data)
            if invite_msg.body and "RTP/SAVP" in invite_msg.body:
                uses_srtp = True
                _LOGGER.info("Siedle uses SRTP — setting up dual crypto contexts")
                
                # Extract Siedle's crypto key for decryption
                for line in invite_msg.body.split('\r\n'):
                    if line.startswith('a=crypto:'):
                        crypto_line = line[9:]
                        break
                
                if crypto_line:
                    try:
                        from .srtp_handler import SRTPCrypto
                        srtp_decrypt = SRTPCrypto.from_base64(crypto_line)
                        if srtp_decrypt:
                            _LOGGER.info("✓ SRTP decrypt context created (Siedle's key)")
                        
                        # Generate our own key for encryption
                        our_crypto_line, srtp_encrypt = SRTPCrypto.generate_sdp_crypto_line()
                        if srtp_encrypt:
                            _LOGGER.info("✓ SRTP encrypt context created (our key)")
                    except Exception as e:
                        _LOGGER.error(f"Failed to setup SRTP crypto: {e}")
        
        # --- Configure RTP bridge ---
        # Set dual SRTP contexts
        if srtp_decrypt:
            self.rtp_bridge.set_srtp_decrypt(srtp_decrypt)
        if srtp_encrypt:
            self.rtp_bridge.set_srtp_encrypt(srtp_encrypt)
        
        # Set remote_b to external phone's RTP endpoint
        ext_rtp = (self._external_call.remote_rtp_host, self._external_call.remote_rtp_port)
        self.rtp_bridge.set_remote_b(ext_rtp)
        _LOGGER.info(f"RTP bridge remote_b set to external: {ext_rtp}")
        
        # Register auto-hangup callback for recording
        def on_recording_stopped():
            _LOGGER.info("Recording finished — auto-hanging up call")
            threading.Thread(target=self._end_call, daemon=True).start()
        self.rtp_bridge.set_on_recording_stopped(on_recording_stopped)
        
        # Start the A→B thread + keepalive (if not already running)
        if not self.rtp_bridge._running:
            self.rtp_bridge.start()
        
        # Start the B→A bridge thread now that remote_b is known
        self.rtp_bridge.start_bridge_b_to_a()
        
        # F8: Set up DTMF detection on the RTP bridge
        self._setup_dtmf_detection()
        
        # --- NAT setup ---
        # Use STUN results from _forward_to_external (cached)
        stun_ip = getattr(self, '_stun_siedle_ip', None)
        stun_port = getattr(self, '_stun_siedle_port', None)
        
        sdp_ip = stun_ip or self._siedle_conn.get_sdp_ip()
        rtp_external_port = stun_port or self.rtp_bridge.local_port_a
        
        _LOGGER.info(f"SDP for Siedle: IP={sdp_ip}, port={rtp_external_port}")
        
        # NAT punch-through BEFORE sending 200 OK
        remote_siedle = (self._siedle_call.remote_rtp_host, self._siedle_call.remote_rtp_port)
        if remote_siedle[0] and remote_siedle[1]:
            self.rtp_bridge.send_nat_punch(remote_siedle, count=5)
        
        # --- Build SDP ---
        if uses_srtp and our_crypto_line:
            media_proto = "RTP/SAVP"
            crypto_attr = f"a=crypto:{our_crypto_line}\r\n"
        else:
            media_proto = "RTP/AVP"
            crypto_attr = ""
        
        sdp = (
            f"v=0\r\n"
            f"o=- {int(time.time())} {int(time.time())} IN IP4 {sdp_ip}\r\n"
            f"s=Siedle HA\r\n"
            f"c=IN IP4 {sdp_ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio {rtp_external_port} {media_proto} 8 101\r\n"
            f"a=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\n"
            f"a=fmtp:101 0-16\r\n"
            f"a=ptime:20\r\n"
            f"{crypto_attr}"
            f"a=sendrecv\r\n"
        )
        
        # --- Send 200 OK to Siedle ---
        if self._siedle_call.invite_data:
            original = SipConnection.parse_message(self._siedle_call.invite_data)
            response = self._siedle_conn.create_response(original, 200, "OK", sdp,
                                                          self.rtp_bridge.local_port_a)
            self._siedle_conn.send(response)
            _LOGGER.info("200 OK sent to Siedle (bridging mode)")
            
            # Post-answer NAT punch
            if remote_siedle[0] and remote_siedle[1]:
                self.rtp_bridge.send_nat_punch(remote_siedle, count=3)
            
            self._siedle_call.state = CallState.CONNECTED
            self._siedle_call.local_rtp_port = self.rtp_bridge.local_port_a
            
            # Start recording if enabled
            if self.recording_enabled and self.recording_path:
                try:
                    _LOGGER.info(f"Starting recording (bridge mode): {self.recording_path}")
                    self._current_recording_file = self.rtp_bridge.start_recording(
                        self.recording_path, duration=self.recording_duration
                    )
                    _LOGGER.info(f"Recording started: {self._current_recording_file}")
                except Exception as e:
                    _LOGGER.error(f"Failed to start recording: {e}")
            
            _LOGGER.info(f"=== Bridge active: Siedle ↔ {ext_rtp[0]}:{ext_rtp[1]} ===")
    
    def _end_call(self):
        """End active call on both sides and fully clean up for next call."""
        _LOGGER.info(f"Ending call... (state={self._state}, siedle_call={'yes' if self._siedle_call else 'no'}, external_call={'yes' if self._external_call else 'no'})")
        
        # F1: Cancel forward timeout timer
        self._cancel_forward_timeout()
        
        # Send BYE to Siedle (any active state, not just CONNECTED)
        if self._siedle_call and self._siedle_conn:
            if self._siedle_call.state in (CallState.CONNECTED, CallState.RECORDING):
                try:
                    bye = self._siedle_conn.create_bye(self._siedle_call)
                    self._siedle_conn.send(bye)
                    _LOGGER.info("BYE sent to Siedle")
                except Exception as e:
                    _LOGGER.warning(f"Failed to send BYE to Siedle: {e}")
            elif self._siedle_call.state in (CallState.RINGING_IN, CallState.RINGING_OUT):
                # Call not yet answered — send CANCEL instead of BYE
                _LOGGER.info(f"Siedle call in {self._siedle_call.state.value} — not sending BYE (not connected)")
        
        # Send BYE to external (any active state)
        if self._external_call and self._external_conn:
            if self._external_call.state in (CallState.CONNECTED, CallState.RECORDING):
                try:
                    bye = self._external_conn.create_bye(self._external_call)
                    self._external_conn.send(bye)
                    _LOGGER.info("BYE sent to external")
                except Exception as e:
                    _LOGGER.warning(f"Failed to send BYE to external: {e}")
            elif self._external_call.state in (CallState.RINGING_IN, CallState.RINGING_OUT):
                _LOGGER.info(f"External call in {self._external_call.state.value} — not sending BYE (not connected)")
        
        # Stop RTP bridge and clean up for reuse
        if self.rtp_bridge:
            try:
                self.rtp_bridge.stop()
                _LOGGER.info("RTP bridge stopped")
            except Exception as e:
                _LOGGER.warning(f"RTP bridge stop error: {e}")
        
        # Clear call state
        self._siedle_call = None
        self._external_call = None
        
        # Clear cached STUN results
        self._stun_siedle_ip = None
        self._stun_siedle_port = None
        
        # Clear cached SDP data (F2)
        self._cached_sdp_ip_b = None
        self._cached_sdp_port_b = None
        self._cached_local_rtp_port_b = None
        self._forward_target_index = 0
        
        self._set_state(CallState.IDLE)
        _LOGGER.info("Call ended — state reset to IDLE, ready for next call")
    
    def hangup(self):
        """Hangup active call (callable from HA)."""
        if self.is_call_active:
            self._end_call()
            return True
        return False
    
    def start(self) -> bool:
        """Start SIP manager."""
        _LOGGER.info("Starting SIP Call Manager...")
        _LOGGER.info(f"Siedle SIP config: host={self.siedle_config.host}, port={self.siedle_config.port}, transport={self.siedle_config.transport.value}")
        
        # Connect to Siedle SIP
        self._siedle_conn = SipConnection(self.siedle_config, name="Siedle-SIP")
        if not self._siedle_conn.register():
            _LOGGER.error("Failed to register with Siedle SIP server!")
            return False
        
        _LOGGER.info("Registered with Siedle SIP - starting listen loop...")
        self._siedle_conn.add_callback(self._handle_siedle_message)
        self._siedle_conn.start_listen_loop()
        
        # Connect to external SIP if configured
        if self.external_config:
            self._external_conn = SipConnection(self.external_config, name="External-SIP")
            if self._external_conn.register():
                self._external_conn.add_callback(self._handle_external_message)
                self._external_conn.start_listen_loop()
            else:
                _LOGGER.warning("Failed to register with external SIP - forwarding disabled")
        
        self._running = True
        
        # Start health monitor thread for auto-reconnection
        self._health_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
        self._health_thread.start()
        
        _LOGGER.info("SIP Call Manager started")
        return True
    
    def _reconnect_siedle(self):
        """Reconnect to Siedle SIP server."""
        _LOGGER.warning("Reconnecting to Siedle SIP server...")
        
        # Stop old connection
        if self._siedle_conn:
            try:
                self._siedle_conn.stop()
            except:
                pass
        
        # Create new connection
        self._siedle_conn = SipConnection(self.siedle_config, name="Siedle-SIP")
        if self._siedle_conn.register():
            _LOGGER.info("Siedle SIP reconnected successfully!")
            self._siedle_conn.add_callback(self._handle_siedle_message)
            self._siedle_conn.start_listen_loop()
            
            # Notify HA that connection is restored
            for callback in self._on_call_state_change_callbacks:
                try:
                    callback(self._state, {"reconnected": True, "source": "siedle"})
                except Exception as e:
                    _LOGGER.debug(f"Reconnect callback error: {e}")
            return True
        else:
            _LOGGER.error("Failed to reconnect to Siedle SIP!")
            return False
    
    def _reconnect_external(self):
        """Reconnect to external SIP server."""
        if not self.external_config:
            return False
        
        _LOGGER.warning("Reconnecting to external SIP server...")
        
        if self._external_conn:
            try:
                self._external_conn.stop()
            except:
                pass
        
        self._external_conn = SipConnection(self.external_config, name="External-SIP")
        if self._external_conn.register():
            _LOGGER.info("External SIP reconnected successfully!")
            self._external_conn.add_callback(self._handle_external_message)
            self._external_conn.start_listen_loop()
            return True
        else:
            _LOGGER.error("Failed to reconnect to external SIP!")
            return False
    
    def _health_monitor_loop(self):
        """Monitor SIP connections and reconnect if needed."""
        _LOGGER.info("SIP health monitor started")
        reconnect_delay = 10  # seconds between reconnect attempts
        
        while self._running:
            time.sleep(5)  # Check every 5 seconds
            
            # Check Siedle connection
            if self._siedle_conn and self._siedle_conn.connection_lost:
                _LOGGER.warning("Siedle SIP connection lost — attempting reconnect...")
                for attempt in range(3):
                    if not self._running:
                        break
                    if self._reconnect_siedle():
                        break
                    _LOGGER.warning(f"Siedle reconnect attempt {attempt + 1}/3 failed, waiting {reconnect_delay}s...")
                    time.sleep(reconnect_delay)
                else:
                    if self._running:
                        _LOGGER.error("Failed to reconnect to Siedle SIP after 3 attempts — will keep trying")
                        time.sleep(60)  # Wait longer before next cycle
                        continue
            
            # Check external connection
            if self._external_conn and self._external_conn.connection_lost:
                _LOGGER.warning("External SIP connection lost — attempting reconnect...")
                for attempt in range(3):
                    if not self._running:
                        break
                    if self._reconnect_external():
                        break
                    _LOGGER.warning(f"External reconnect attempt {attempt + 1}/3 failed, waiting {reconnect_delay}s...")
                    time.sleep(reconnect_delay)
        
        _LOGGER.info("SIP health monitor stopped")
    
    def stop(self):
        """Stop SIP manager."""
        _LOGGER.info("Stopping SIP Call Manager...")
        self._running = False
        
        if self._siedle_call:
            self._end_call()
        
        if self._siedle_conn:
            self._siedle_conn.stop()
        
        if self._external_conn:
            self._external_conn.stop()
        
        # Wait for health monitor
        if hasattr(self, '_health_thread') and self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=10.0)
        
        _LOGGER.info("SIP Call Manager stopped")
