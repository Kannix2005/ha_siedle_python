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

_LOGGER = logging.getLogger(__name__)


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
        return self.headers.get("Via") or self.headers.get("v")
    
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
        
    @property
    def registered(self) -> bool:
        return self._registered
    
    @property
    def connected(self) -> bool:
        return self._connected
    
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
            
            # Parse headers
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    name, value = line.split(":", 1)
                    msg.headers[name.strip()] = value.strip()
            
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
    
    def create_invite(self, to_uri: str, local_rtp_port: int, call_id: Optional[str] = None) -> Tuple[bytes, SipCall]:
        """Create SIP INVITE message with SDP."""
        local_ip = self._get_local_ip()
        call_id = call_id or str(uuid.uuid4())
        from_tag = uuid.uuid4().hex[:8]
        branch = uuid.uuid4().hex[:12]
        cseq = 1
        
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        display_name = self.config.display_name or "Siedle Türstation"
        
        # Create SDP body
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
        """Create SIP response to a request."""
        local_ip = self._get_local_ip()
        to_tag = uuid.uuid4().hex[:8]
        transport_str = "TLS" if self.config.transport == SipTransport.TLS else "UDP"
        
        # Build To header with tag for 200 OK
        to_header = request.to_header
        if status_code == 200 and ";tag=" not in to_header:
            to_header = f"{to_header};tag={to_tag}"
        
        lines = [
            f"SIP/2.0 {status_code} {status_text}",
            f"Via: {request.via}",
            f"From: {request.from_header}",
            f"To: {to_header}",
            f"Call-ID: {request.call_id}",
            f"CSeq: {request.cseq}",
        ]
        
        if status_code == 200 and request.method == "INVITE":
            lines.append(f"Contact: <sip:{self.config.username}@{local_ip}:{self._local_port};transport={transport_str.lower()}>")
        
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
                    
                    if msg.status_code == 200:
                        _LOGGER.info(f"{self.name}: Registration successful!")
                        self._registered = True
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
    
    def recv(self, timeout: float = 0.1) -> Optional[SipMessage]:
        """Receive and parse message with timeout."""
        try:
            if self.config.transport != SipTransport.UDP:
                self._socket.setblocking(False)
            self._socket.settimeout(timeout)
            data = self._socket.recv(4096)
            if data:
                return self.parse_message(data)
        except socket.timeout:
            pass
        except ssl.SSLWantReadError:
            pass
        except BlockingIOError:
            pass
        except Exception as e:
            if self._running:
                _LOGGER.debug(f"{self.name}: Receive error: {e}")
        return None
    
    def start_listen_loop(self):
        """Start background listen loop."""
        if self._listen_thread and self._listen_thread.is_alive():
            return
        
        self._running = True
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()
    
    def _listen_loop(self):
        """Background listen loop."""
        _LOGGER.info(f"{self.name}: Listen loop started - waiting for incoming SIP messages...")
        while self._running:
            msg = self.recv(timeout=0.5)
            if msg and (msg.method or msg.status_code):
                _LOGGER.debug(f"{self.name}: Received: method={msg.method}, status={msg.status_code}")
                self._notify_callbacks(msg)
        _LOGGER.info(f"{self.name}: Listen loop ended")
    
    def stop(self):
        """Stop connection and listen loop."""
        self._running = False
        self._registered = False
        self._connected = False
        
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
        
        _LOGGER.info(f"{self.name}: Connection closed")


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
    ):
        self.siedle_config = siedle_config
        self.external_config = external_config
        self.forward_to_number = forward_to_number
        self.forward_from_number = forward_from_number
        self.auto_answer = auto_answer
        
        # Connections
        self._siedle_conn: Optional[SipConnection] = None
        self._external_conn: Optional[SipConnection] = None
        
        # Active calls
        self._siedle_call: Optional[SipCall] = None
        self._external_call: Optional[SipCall] = None
        
        # State
        self._state = CallState.IDLE
        self._running = False
        
        # Callbacks
        self._on_doorbell: Optional[Callable[[dict], None]] = None
        self._on_call_state_change: Optional[Callable[[CallState, dict], None]] = None
        self._on_incoming_external: Optional[Callable[[dict], None]] = None
        
        # RTP Bridge (will be set externally)
        self.rtp_bridge: Optional[Any] = None
        
        # Recording
        self._recording_task: Optional[asyncio.Task] = None
    
    @property
    def state(self) -> CallState:
        return self._state
    
    @property
    def is_call_active(self) -> bool:
        return self._state in (CallState.CONNECTED, CallState.RECORDING, CallState.RINGING_IN, CallState.RINGING_OUT)
    
    def set_on_doorbell(self, callback: Callable[[dict], None]):
        """Set doorbell callback."""
        self._on_doorbell = callback
    
    def set_on_call_state_change(self, callback: Callable[[CallState, dict], None]):
        """Set call state change callback."""
        self._on_call_state_change = callback
    
    def set_on_incoming_external(self, callback: Callable[[dict], None]):
        """Set incoming external call callback."""
        self._on_incoming_external = callback
    
    def _set_state(self, new_state: CallState, data: Optional[dict] = None):
        """Update call state and notify."""
        old_state = self._state
        self._state = new_state
        _LOGGER.info(f"SIP Call State: {old_state.value} -> {new_state.value}")
        
        if self._on_call_state_change:
            try:
                self._on_call_state_change(new_state, data or {})
            except Exception as e:
                _LOGGER.error(f"Call state callback error: {e}")
    
    def _handle_siedle_message(self, msg: SipMessage):
        """Handle message from Siedle SIP server."""
        _LOGGER.debug(f"Siedle message: method={msg.method}, status={msg.status_code}, from={msg.from_header}")
        
        if msg.is_request and msg.method == "INVITE":
            _LOGGER.warning(f"🔔 SIEDLE INVITE - DOORBELL! From: {msg.from_header}")
            
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
            
            _LOGGER.info(f"Doorbell data: caller_id={caller_id}, call_id={msg.call_id}")
            
            # Notify doorbell callback
            if self._on_doorbell:
                try:
                    _LOGGER.debug("Calling doorbell callback...")
                    self._on_doorbell(data)
                    _LOGGER.debug("Doorbell callback completed")
                except Exception as e:
                    _LOGGER.error(f"Doorbell callback error: {e}")
                    _LOGGER.exception(e)
            else:
                _LOGGER.warning("No doorbell callback registered!")
            
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
            
            # If forwarding enabled and external server connected
            if self.forward_to_number and self._external_conn and self._external_conn.registered:
                self._forward_to_external()
            elif self.auto_answer:
                self._answer_siedle_call()
        
        elif msg.is_request and msg.method == "BYE":
            _LOGGER.info("Siedle: BYE received - call ended")
            self._send_ok_response(self._siedle_conn, msg)
            self._end_call()
        
        elif msg.is_request and msg.method == "CANCEL":
            _LOGGER.info("Siedle: CANCEL received")
            self._send_ok_response(self._siedle_conn, msg)
            self._set_state(CallState.IDLE)
    
    def _handle_external_message(self, msg: SipMessage):
        """Handle message from external SIP server."""
        if msg.is_request and msg.method == "INVITE":
            _LOGGER.info(f"External INVITE from: {msg.from_header}")
            
            # Check if from allowed number
            if self.forward_from_number:
                if self.forward_from_number not in (msg.from_header or ""):
                    _LOGGER.warning(f"Rejecting call from unauthorized number: {msg.from_header}")
                    # Send 403 Forbidden
                    response = self._external_conn.create_response(msg, 403, "Forbidden")
                    self._external_conn.send(response)
                    return
            
            # Notify callback
            if self._on_incoming_external:
                try:
                    self._on_incoming_external({
                        "from": msg.from_header,
                        "call_id": msg.call_id,
                    })
                except Exception as e:
                    _LOGGER.error(f"Incoming external callback error: {e}")
            
            # Store call and forward to door
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
            
            # TODO: Forward to Siedle door station
            self._set_state(CallState.RINGING_IN, {"source": "external", "from": msg.from_header})
        
        elif not msg.is_request:
            # Response to our INVITE
            if msg.status_code == 180 or msg.status_code == 183:
                _LOGGER.info("External: Ringing...")
            elif msg.status_code == 200:
                _LOGGER.info("External: Call answered!")
                if self._external_call:
                    self._external_call.to_tag = self._extract_tag(msg.to_header)
                    self._external_call.state = CallState.CONNECTED
                    self._external_call.remote_rtp_port = msg.get_sdp_media_port() or 0
                    self._external_call.remote_rtp_host = msg.get_sdp_connection_ip()
                    
                    # Send ACK
                    ack = self._external_conn.create_ack(self._external_call, msg)
                    self._external_conn.send(ack)
                    
                    # Now answer Siedle call
                    self._answer_siedle_call()
                    self._set_state(CallState.CONNECTED)
            elif msg.status_code >= 400:
                _LOGGER.warning(f"External: Call rejected: {msg.status_code} {msg.status_text}")
                self._set_state(CallState.IDLE)
        
        elif msg.is_request and msg.method == "BYE":
            _LOGGER.info("External: BYE received")
            self._send_ok_response(self._external_conn, msg)
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
        """Forward incoming Siedle call to external SIP server."""
        if not self._external_conn or not self._external_conn.registered:
            _LOGGER.warning("Cannot forward: External SIP not connected")
            return
        
        if not self.forward_to_number:
            _LOGGER.warning("Cannot forward: No forward_to_number configured")
            return
        
        _LOGGER.info(f"Forwarding doorbell to {self.forward_to_number}...")
        
        # Send 100 Trying to Siedle
        # TODO: Implement proper response
        
        # Create INVITE to external server
        to_uri = f"sip:{self.forward_to_number}@{self.external_config.host}"
        local_rtp_port = 20000  # TODO: Dynamic port allocation
        
        invite_msg, call = self._external_conn.create_invite(to_uri, local_rtp_port)
        self._external_call = call
        self._external_conn.send(invite_msg)
        
        self._set_state(CallState.RINGING_OUT, {"target": self.forward_to_number})
    
    def _answer_siedle_call(self):
        """Send 200 OK to Siedle INVITE."""
        if not self._siedle_call or not self._siedle_conn:
            return
        
        local_ip = self._siedle_conn._get_local_ip()
        local_rtp_port = 20002  # TODO: Dynamic port allocation
        
        sdp = (
            f"v=0\r\n"
            f"o=- {int(time.time())} {int(time.time())} IN IP4 {local_ip}\r\n"
            f"s=Siedle HA\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio {local_rtp_port} RTP/AVP 0 8 101\r\n"
            f"a=rtpmap:0 PCMU/8000\r\n"
            f"a=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\n"
            f"a=sendrecv\r\n"
        )
        
        # Parse original INVITE to create proper response
        if self._siedle_call.invite_data:
            original = SipConnection.parse_message(self._siedle_call.invite_data)
            response = self._siedle_conn.create_response(original, 200, "OK", sdp, local_rtp_port)
            self._siedle_conn.send(response)
            
            self._siedle_call.state = CallState.CONNECTED
            self._siedle_call.local_rtp_port = local_rtp_port
            _LOGGER.info("Siedle call answered")
    
    def _end_call(self):
        """End active call on both sides."""
        _LOGGER.info("Ending call...")
        
        # Send BYE to Siedle
        if self._siedle_call and self._siedle_conn and self._siedle_call.state == CallState.CONNECTED:
            bye = self._siedle_conn.create_bye(self._siedle_call)
            try:
                self._siedle_conn.send(bye)
            except:
                pass
        
        # Send BYE to external
        if self._external_call and self._external_conn and self._external_call.state == CallState.CONNECTED:
            bye = self._external_conn.create_bye(self._external_call)
            try:
                self._external_conn.send(bye)
            except:
                pass
        
        # Stop RTP bridge
        if self.rtp_bridge:
            try:
                self.rtp_bridge.stop()
            except:
                pass
        
        self._siedle_call = None
        self._external_call = None
        self._set_state(CallState.IDLE)
    
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
        _LOGGER.info("SIP Call Manager started")
        return True
    
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
        
        _LOGGER.info("SIP Call Manager stopped")
