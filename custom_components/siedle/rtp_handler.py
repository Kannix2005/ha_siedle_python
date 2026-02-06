"""RTP Handler for Siedle integration.

Handles RTP audio bridging between two SIP endpoints and recording.
"""
import asyncio
import logging
import socket
import struct
import threading
import time
import wave
import os
from dataclasses import dataclass
from typing import Optional, Tuple, Callable
from datetime import datetime

_LOGGER = logging.getLogger(__name__)

# RTP Header format
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |V=2|P|X|  CC   |M|     PT      |       sequence number         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           timestamp                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           synchronization source (SSRC) identifier            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


@dataclass
class RtpPacket:
    """Parsed RTP packet."""
    version: int
    padding: bool
    extension: bool
    cc: int
    marker: bool
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes
    
    @classmethod
    def parse(cls, data: bytes) -> Optional["RtpPacket"]:
        """Parse RTP packet from bytes."""
        if len(data) < 12:
            return None
        
        try:
            # Parse first two bytes
            first_byte = data[0]
            second_byte = data[1]
            
            version = (first_byte >> 6) & 0x03
            padding = bool((first_byte >> 5) & 0x01)
            extension = bool((first_byte >> 4) & 0x01)
            cc = first_byte & 0x0F
            
            marker = bool((second_byte >> 7) & 0x01)
            payload_type = second_byte & 0x7F
            
            # Parse sequence, timestamp, ssrc
            sequence = struct.unpack("!H", data[2:4])[0]
            timestamp = struct.unpack("!I", data[4:8])[0]
            ssrc = struct.unpack("!I", data[8:12])[0]
            
            # Skip CSRC if present
            header_len = 12 + (cc * 4)
            
            # Handle extension header
            if extension and len(data) > header_len + 4:
                ext_len = struct.unpack("!H", data[header_len + 2:header_len + 4])[0]
                header_len += 4 + (ext_len * 4)
            
            payload = data[header_len:]
            
            return cls(
                version=version,
                padding=padding,
                extension=extension,
                cc=cc,
                marker=marker,
                payload_type=payload_type,
                sequence=sequence,
                timestamp=timestamp,
                ssrc=ssrc,
                payload=payload,
            )
        except Exception as e:
            _LOGGER.debug(f"RTP parse error: {e}")
            return None
    
    def to_bytes(self) -> bytes:
        """Serialize RTP packet to bytes."""
        first_byte = (self.version << 6) | (int(self.padding) << 5) | (int(self.extension) << 4) | self.cc
        second_byte = (int(self.marker) << 7) | self.payload_type
        
        header = struct.pack(
            "!BBHII",
            first_byte,
            second_byte,
            self.sequence,
            self.timestamp,
            self.ssrc,
        )
        
        return header + self.payload


def pcmu_to_linear(pcmu_data: bytes) -> bytes:
    """Convert μ-law (PCMU) audio to 16-bit linear PCM."""
    # μ-law decompression table
    ULAW_TABLE = [
        -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
        -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
        -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
        -11900, -11388, -10876, -10364, -9852, -9340, -8828, -8316,
        -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
        -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
        -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
        -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
        -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
        -1372, -1308, -1244, -1180, -1116, -1052, -988, -924,
        -876, -844, -812, -780, -748, -716, -684, -652,
        -620, -588, -556, -524, -492, -460, -428, -396,
        -372, -356, -340, -324, -308, -292, -276, -260,
        -244, -228, -212, -196, -180, -164, -148, -132,
        -120, -112, -104, -96, -88, -80, -72, -64,
        -56, -48, -40, -32, -24, -16, -8, 0,
        32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
        23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
        15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
        11900, 11388, 10876, 10364, 9852, 9340, 8828, 8316,
        7932, 7676, 7420, 7164, 6908, 6652, 6396, 6140,
        5884, 5628, 5372, 5116, 4860, 4604, 4348, 4092,
        3900, 3772, 3644, 3516, 3388, 3260, 3132, 3004,
        2876, 2748, 2620, 2492, 2364, 2236, 2108, 1980,
        1884, 1820, 1756, 1692, 1628, 1564, 1500, 1436,
        1372, 1308, 1244, 1180, 1116, 1052, 988, 924,
        876, 844, 812, 780, 748, 716, 684, 652,
        620, 588, 556, 524, 492, 460, 428, 396,
        372, 356, 340, 324, 308, 292, 276, 260,
        244, 228, 212, 196, 180, 164, 148, 132,
        120, 112, 104, 96, 88, 80, 72, 64,
        56, 48, 40, 32, 24, 16, 8, 0,
    ]
    
    result = bytearray()
    for byte in pcmu_data:
        # Invert all bits (μ-law storage format)
        sample = ULAW_TABLE[byte ^ 0xFF]
        result.extend(struct.pack("<h", sample))
    return bytes(result)


def pcma_to_linear(pcma_data: bytes) -> bytes:
    """Convert A-law (PCMA) audio to 16-bit linear PCM."""
    ALAW_TABLE = [
        -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
        -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
        -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
        -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
        -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944,
        -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
        -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472,
        -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568,
        -344, -328, -376, -360, -280, -264, -312, -296,
        -472, -456, -504, -488, -408, -392, -440, -424,
        -88, -72, -120, -104, -24, -8, -56, -40,
        -216, -200, -248, -232, -152, -136, -184, -168,
        -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
        -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
        -688, -656, -752, -720, -560, -528, -624, -592,
        -944, -912, -1008, -976, -816, -784, -880, -848,
        5504, 5248, 6016, 5760, 4480, 4224, 4992, 4736,
        7552, 7296, 8064, 7808, 6528, 6272, 7040, 6784,
        2752, 2624, 3008, 2880, 2240, 2112, 2496, 2368,
        3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392,
        22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
        30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
        11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472,
        15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
        344, 328, 376, 360, 280, 264, 312, 296,
        472, 456, 504, 488, 408, 392, 440, 424,
        88, 72, 120, 104, 24, 8, 56, 40,
        216, 200, 248, 232, 152, 136, 184, 168,
        1376, 1312, 1504, 1440, 1120, 1056, 1248, 1184,
        1888, 1824, 2016, 1952, 1632, 1568, 1760, 1696,
        688, 656, 752, 720, 560, 528, 624, 592,
        944, 912, 1008, 976, 816, 784, 880, 848,
    ]
    
    result = bytearray()
    for byte in pcma_data:
        # A-law uses XOR with 0x55
        sample = ALAW_TABLE[byte ^ 0x55]
        result.extend(struct.pack("<h", sample))
    return bytes(result)


class AudioRecorder:
    """Records RTP audio to WAV file."""
    
    def __init__(self, filepath: str, sample_rate: int = 8000, channels: int = 1):
        self.filepath = filepath
        self.sample_rate = sample_rate
        self.channels = channels
        self._wav_file: Optional[wave.Wave_write] = None
        self._recording = False
        self._lock = threading.Lock()
        self._bytes_written = 0
        
    def start(self):
        """Start recording."""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        
        self._wav_file = wave.open(self.filepath, 'wb')
        self._wav_file.setnchannels(self.channels)
        self._wav_file.setsampwidth(2)  # 16-bit
        self._wav_file.setframerate(self.sample_rate)
        self._recording = True
        self._bytes_written = 0
        _LOGGER.info(f"Recording started: {self.filepath}")
    
    def write_rtp(self, packet: RtpPacket):
        """Write RTP packet payload to file."""
        if not self._recording or not self._wav_file:
            return
        
        try:
            # Convert based on payload type
            if packet.payload_type == 0:  # PCMU
                pcm_data = pcmu_to_linear(packet.payload)
            elif packet.payload_type == 8:  # PCMA
                pcm_data = pcma_to_linear(packet.payload)
            else:
                # Unknown codec, skip
                return
            
            with self._lock:
                self._wav_file.writeframes(pcm_data)
                self._bytes_written += len(pcm_data)
                
        except Exception as e:
            _LOGGER.error(f"Recording write error: {e}")
    
    def stop(self) -> str:
        """Stop recording and return filepath."""
        self._recording = False
        if self._wav_file:
            try:
                self._wav_file.close()
            except:
                pass
            self._wav_file = None
        
        duration = self._bytes_written / (self.sample_rate * 2)  # 16-bit = 2 bytes per sample
        _LOGGER.info(f"Recording stopped: {self.filepath} ({duration:.1f}s)")
        return self.filepath
    
    @property
    def is_recording(self) -> bool:
        return self._recording


class RtpBridge:
    """
    Bridges RTP audio between two endpoints.
    
    Can forward audio bidirectionally and record incoming audio.
    """
    
    def __init__(self):
        # Sockets
        self._socket_a: Optional[socket.socket] = None  # Siedle side
        self._socket_b: Optional[socket.socket] = None  # External side
        
        # Remote endpoints
        self._remote_a: Optional[Tuple[str, int]] = None
        self._remote_b: Optional[Tuple[str, int]] = None
        
        # Local ports
        self.local_port_a: int = 0
        self.local_port_b: int = 0
        
        # State
        self._running = False
        self._thread_a_to_b: Optional[threading.Thread] = None
        self._thread_b_to_a: Optional[threading.Thread] = None
        self._thread_keepalive: Optional[threading.Thread] = None
        
        # Recording
        self._recorder: Optional[AudioRecorder] = None
        
        # SRTP Support
        self._srtp_crypto: Optional[Any] = None
        
        # Statistics
        self._packets_a_to_b = 0
        self._packets_b_to_a = 0
        
        # Callbacks
        self._on_audio_received: Optional[Callable[[RtpPacket, str], None]] = None
        self._on_recording_stopped: Optional[Callable[[], None]] = None
    
    def stun_discover_external_port(self) -> Tuple[Optional[str], Optional[int]]:
        """Discover external IP and port via STUN using the actual RTP socket.
        
        This sends a STUN Binding Request from socket_a (the Siedle-facing RTP socket),
        so the returned external port is the exact NAT mapping for this socket.
        Must be called after setup() but before start().
        
        Returns:
            (external_ip, external_port) or (None, None) on failure
        """
        if not self._socket_a:
            _LOGGER.warning("Cannot run STUN - RTP socket not set up yet")
            return None, None
        
        try:
            from .stun_client import discover_external_address
            ip, port = discover_external_address(local_socket=self._socket_a)
            if ip and port:
                _LOGGER.info(f"STUN from RTP socket: external {ip}:{port} (local port {self.local_port_a})")
            else:
                _LOGGER.warning(f"STUN from RTP socket failed (local port {self.local_port_a})")
            return ip, port
        except Exception as e:
            _LOGGER.error(f"STUN discovery error: {e}")
            return None, None

    def set_srtp_crypto(self, crypto):
        """Set SRTP crypto handler for decryption.
        
        Args:
            crypto: SRTPCrypto instance
        """
        self._srtp_crypto = crypto
        if crypto:
            _LOGGER.info("SRTP decryption enabled for RTP bridge")
    
    def set_on_audio_received(self, callback: Callable[[RtpPacket, str], None]):
        """Set callback for received audio packets."""
        self._on_audio_received = callback
    
    def set_on_recording_stopped(self, callback: Callable[[], None]):
        """Set callback for when recording stops (e.g., after duration expires).
        
        This allows the SIP manager to auto-hangup when recording finishes.
        """
        self._on_recording_stopped = callback
    
    def _allocate_port(self) -> Tuple[socket.socket, int]:
        """Allocate a UDP socket on a random available port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 0))
        sock.settimeout(0.1)
        port = sock.getsockname()[1]
        return sock, port
    
    def setup(
        self,
        remote_a: Tuple[str, int],  # Siedle endpoint
        remote_b: Optional[Tuple[str, int]] = None,  # External endpoint (optional)
    ) -> Tuple[int, int]:
        """
        Setup RTP bridge sockets.
        
        Returns (local_port_a, local_port_b) for SDP negotiation.
        """
        # Allocate sockets
        self._socket_a, self.local_port_a = self._allocate_port()
        self._socket_b, self.local_port_b = self._allocate_port()
        
        self._remote_a = remote_a
        self._remote_b = remote_b
        
        _LOGGER.info(f"RTP Bridge setup: local ports {self.local_port_a}/{self.local_port_b}")
        _LOGGER.info(f"RTP Bridge remotes: A={remote_a}, B={remote_b}")
        
        return self.local_port_a, self.local_port_b
    
    def start(self):
        """Start the RTP bridge."""
        if self._running:
            return
        
        self._running = True
        self._packets_a_to_b = 0
        self._packets_b_to_a = 0
        
        # Start forwarding threads
        self._thread_a_to_b = threading.Thread(target=self._forward_a_to_b, daemon=True)
        self._thread_a_to_b.start()
        
        if self._remote_b:
            self._thread_b_to_a = threading.Thread(target=self._forward_b_to_a, daemon=True)
            self._thread_b_to_a.start()
        
        # Start keepalive thread to send continuous RTP silence to Siedle
        # This keeps the NAT pinhole open and signals we're an active endpoint
        if self._remote_a:
            self._thread_keepalive = threading.Thread(target=self._send_keepalive, daemon=True)
            self._thread_keepalive.start()
        
        _LOGGER.info("RTP Bridge started")
    
    def send_nat_punch(self, remote: Tuple[str, int], count: int = 3):
        """Send NAT punch-through packets to open NAT for incoming RTP.
        
        Sends small dummy packets from our RTP socket to the remote endpoint.
        This creates a NAT mapping that allows the remote side to send RTP 
        packets back to us through the same NAT hole.
        
        This is similar to how PJSIP handles symmetric RTP behind NAT.
        
        Args:
            remote: (host, port) of remote RTP endpoint
            count: Number of punch-through packets to send
        """
        if not self._socket_a or not remote[0] or not remote[1]:
            return
        
        try:
            _LOGGER.info(f"Sending {count} NAT punch-through RTP packets to {remote[0]}:{remote[1]}")
            
            for i in range(count):
                # Send a minimal valid RTP packet (header only, no payload)
                # V=2, P=0, X=0, CC=0, M=0, PT=8 (PCMA), seq=0, ts=0, ssrc=random
                import os
                ssrc = int.from_bytes(os.urandom(4), 'big')
                rtp_header = struct.pack("!BBHII",
                    0x80,  # V=2, P=0, X=0, CC=0
                    8,     # M=0, PT=8 (PCMA)
                    i,     # sequence number
                    0,     # timestamp
                    ssrc,  # SSRC
                )
                # Add 160 bytes of silence (A-law silence = 0xD5)
                silence = bytes([0xD5] * 160)
                packet = rtp_header + silence
                
                self._socket_a.sendto(packet, remote)
                time.sleep(0.02)  # 20ms between packets
            
            _LOGGER.info(f"NAT punch-through sent: {count} packets to {remote[0]}:{remote[1]}")
        except Exception as e:
            _LOGGER.error(f"NAT punch-through error: {e}")
    
    def _send_keepalive(self):
        """Send continuous RTP silence to Siedle to keep NAT pinhole open.
        
        Sends A-law silence frames every 20ms. This:
        1. Keeps the NAT mapping alive (UDP state table refresh)
        2. Signals to Asterisk that we're an active media endpoint
        3. Implements symmetric RTP (PJSIP does this by default)
        """
        if not self._socket_a or not self._remote_a:
            return
        
        _LOGGER.info(f"RTP keepalive started: sending silence to {self._remote_a[0]}:{self._remote_a[1]} every 20ms")
        
        ssrc = int.from_bytes(os.urandom(4), 'big')
        seq = 100  # Start after NAT punch sequences
        ts = 0
        packets_sent = 0
        
        try:
            while self._running:
                rtp_header = struct.pack("!BBHII",
                    0x80,   # V=2, P=0, X=0, CC=0
                    8,      # M=0, PT=8 (PCMA)
                    seq & 0xFFFF,
                    ts & 0xFFFFFFFF,
                    ssrc,
                )
                silence = bytes([0xD5] * 160)  # A-law silence, 20ms at 8kHz
                packet = rtp_header + silence
                
                self._socket_a.sendto(packet, self._remote_a)
                
                seq += 1
                ts += 160  # 160 samples = 20ms at 8kHz
                packets_sent += 1
                
                if packets_sent == 1:
                    _LOGGER.info(f"First RTP keepalive packet sent to {self._remote_a}")
                elif packets_sent == 50:  # After 1 second
                    _LOGGER.info(f"RTP keepalive: {packets_sent} packets sent (1 second)")
                elif packets_sent % 500 == 0:  # Every 10 seconds
                    _LOGGER.debug(f"RTP keepalive: {packets_sent} packets sent")
                
                time.sleep(0.02)  # 20ms
        except Exception as e:
            if self._running:
                _LOGGER.error(f"RTP keepalive error: {e}")
        
        _LOGGER.info(f"RTP keepalive stopped after {packets_sent} packets")
    
    def _forward_a_to_b(self):
        """Forward packets from A (Siedle) to B (External)."""
        _LOGGER.info(f"RTP forward A->B thread started - listening on port {self.local_port_a}, waiting for packets from {self._remote_a}...")
        if self._srtp_crypto:
            _LOGGER.info("SRTP decryption enabled - will decrypt incoming SRTP packets")
        
        packet_count = 0
        decryption_errors = 0
        last_log_time = time.time()
        timeout_warning_shown = False
        
        while self._running:
            try:
                data, addr = self._socket_a.recvfrom(2048)
                if data:
                    # Log first few packets for debugging
                    if packet_count < 5:
                        _LOGGER.info(f"✓ RTP packet received! From {addr}, size={len(data)} bytes")
                    
                    # Decrypt SRTP if enabled
                    rtp_data = data
                    if self._srtp_crypto:
                        decrypted = self._srtp_crypto.decrypt_rtp(data)
                        if decrypted:
                            rtp_data = decrypted
                            if packet_count < 3:
                                _LOGGER.info(f"✓ SRTP decrypted: {len(data)} -> {len(rtp_data)} bytes")
                        else:
                            decryption_errors += 1
                            if decryption_errors < 5:
                                _LOGGER.warning(f"SRTP decryption failed for packet {packet_count}")
                            continue  # Skip this packet
                    
                    packet = RtpPacket.parse(rtp_data)
                    if packet:
                        self._packets_a_to_b += 1
                        packet_count += 1
                        
                        # Log every 10 seconds
                        current_time = time.time()
                        if current_time - last_log_time >= 10.0:
                            _LOGGER.info(f"RTP: {packet_count} packets received, recording={self._recorder is not None}, decryption_errors={decryption_errors}")
                            last_log_time = current_time
                        
                        # Record if enabled
                        if self._recorder:
                            self._recorder.write_rtp(packet)
                        
                        # Forward to B if configured
                        if self._remote_b and self._socket_b:
                            # Send decrypted RTP (not SRTP)
                            self._socket_b.sendto(rtp_data, self._remote_b)
                        
                        # Notify callback
                        if self._on_audio_received:
                            self._on_audio_received(packet, "a")
                    else:
                        _LOGGER.warning(f"Failed to parse RTP packet from {addr}")
                            
            except socket.timeout:
                # Show warning after 5 seconds of no packets
                current_time = time.time()
                if not timeout_warning_shown and current_time - last_log_time >= 5.0:
                    _LOGGER.warning(f"⚠ No RTP packets received after 5 seconds - call established but no audio")
                    _LOGGER.warning(f"Listening on port {self.local_port_a}, expecting packets from {self._remote_a}")
                    if self._srtp_crypto:
                        _LOGGER.warning("SRTP is enabled - waiting for encrypted packets")
                    timeout_warning_shown = True
                pass
            except Exception as e:
                if self._running:
                    _LOGGER.error(f"RTP A->B error: {e}", exc_info=True)
        
        _LOGGER.info(f"RTP forward A->B thread ended - received {packet_count} packets total, {decryption_errors} decryption errors")
    
    def _forward_b_to_a(self):
        """Forward packets from B (External) to A (Siedle)."""
        _LOGGER.debug("RTP forward B->A thread started")
        while self._running:
            try:
                data, addr = self._socket_b.recvfrom(2048)
                if data:
                    packet = RtpPacket.parse(data)
                    if packet:
                        self._packets_b_to_a += 1
                        
                        # Forward to A
                        if self._remote_a and self._socket_a:
                            self._socket_a.sendto(data, self._remote_a)
                        
                        # Notify callback
                        if self._on_audio_received:
                            self._on_audio_received(packet, "b")
                            
            except socket.timeout:
                pass
            except Exception as e:
                if self._running:
                    _LOGGER.debug(f"RTP B->A error: {e}")
        
        _LOGGER.debug("RTP forward B->A thread ended")
    
    def start_recording(self, filepath: str, duration: Optional[int] = None) -> str:
        """
        Start recording incoming audio.
        
        Args:
            filepath: Path to save WAV file
            duration: Optional max duration in seconds
            
        Returns:
            The filepath that will be used
        """
        # Add timestamp to filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base, ext = os.path.splitext(filepath)
        if not ext:
            ext = ".wav"
        final_path = f"{base}_{timestamp}{ext}"
        
        self._recorder = AudioRecorder(final_path)
        self._recorder.start()
        
        # Auto-stop after duration if specified
        if duration:
            def stop_after_duration():
                time.sleep(duration)
                if self._recorder and self._recorder.is_recording:
                    self.stop_recording()
                    # Notify that recording has stopped (for auto-hangup)
                    if self._on_recording_stopped:
                        try:
                            self._on_recording_stopped()
                        except Exception as e:
                            _LOGGER.error(f"Recording stopped callback error: {e}")
            
            threading.Thread(target=stop_after_duration, daemon=True).start()
        
        return final_path
    
    def stop_recording(self) -> Optional[str]:
        """Stop recording and return filepath."""
        if self._recorder:
            filepath = self._recorder.stop()
            self._recorder = None
            return filepath
        return None
    
    def stop(self):
        """Stop the RTP bridge."""
        _LOGGER.info("Stopping RTP Bridge...")
        self._running = False
        
        # Stop recording
        if self._recorder:
            self._recorder.stop()
            self._recorder = None
        
        # Close sockets
        if self._socket_a:
            try:
                self._socket_a.close()
            except:
                pass
            self._socket_a = None
        
        if self._socket_b:
            try:
                self._socket_b.close()
            except:
                pass
            self._socket_b = None
        
        _LOGGER.info(f"RTP Bridge stopped. Stats: A->B={self._packets_a_to_b}, B->A={self._packets_b_to_a}")
    
    @property
    def is_recording(self) -> bool:
        return self._recorder is not None and self._recorder.is_recording
    
    @property
    def stats(self) -> dict:
        return {
            "packets_a_to_b": self._packets_a_to_b,
            "packets_b_to_a": self._packets_b_to_a,
            "is_recording": self.is_recording,
        }
