"""SRTP Handler for encrypted RTP audio.

Implements SRTP (Secure RTP) decryption for Siedle audio streams.
"""
import base64
import hashlib
import hmac
import logging
import os
import struct
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

_LOGGER = logging.getLogger(__name__)


class SRTPCrypto:
    """Handle SRTP encryption/decryption."""
    
    def __init__(self, master_key: bytes, master_salt: bytes):
        """Initialize SRTP crypto.
        
        Args:
            master_key: 16-byte AES master key
            master_salt: 14-byte master salt
        """
        self.master_key = master_key
        self.master_salt = master_salt
        self._session_keys = {}
        
        _LOGGER.debug(f"SRTP initialized: key={len(master_key)} bytes, salt={len(master_salt)} bytes")
    
    @classmethod
    def from_base64(cls, crypto_suite: str) -> Optional["SRTPCrypto"]:
        """Create SRTP crypto from SDP crypto attribute.
        
        Example: "AES_CM_128_HMAC_SHA1_80 inline:hVBnwvvAf8nCFBAI0vJRa7sTd38YeTkS22otYkiP"
        
        Args:
            crypto_suite: The crypto suite string from SDP
            
        Returns:
            SRTPCrypto instance or None if parsing failed
        """
        import base64
        
        try:
            # Extract key material from "inline:..." format
            if "inline:" not in crypto_suite:
                _LOGGER.error(f"Invalid crypto suite format: {crypto_suite}")
                return None
            
            key_material_b64 = crypto_suite.split("inline:")[1].strip()
            key_material = base64.b64decode(key_material_b64)
            
            # AES_CM_128_HMAC_SHA1_80 uses:
            # - 16 bytes master key
            # - 14 bytes master salt
            # Total: 30 bytes
            if len(key_material) < 30:
                _LOGGER.error(f"Key material too short: {len(key_material)} bytes (expected 30)")
                return None
            
            master_key = key_material[:16]
            master_salt = key_material[16:30]
            
            _LOGGER.info(f"Parsed SRTP crypto: key={len(master_key)}B, salt={len(master_salt)}B")
            
            return cls(master_key, master_salt)
            
        except Exception as e:
            _LOGGER.error(f"Failed to parse crypto suite: {e}")
            return None
    
    @staticmethod
    def generate_sdp_crypto_line() -> Tuple[str, "SRTPCrypto"]:
        """Generate a new SRTP crypto line for SDP answer.
        
        Creates random 16-byte key + 14-byte salt (30 bytes total),
        base64 encodes them, and formats as SDP a=crypto: attribute value.
        Also returns the SRTPCrypto instance for encrypting outbound packets.
        
        Returns:
            Tuple of (sdp_line like "1 AES_CM_128_HMAC_SHA1_80 inline:<base64key>",
                       SRTPCrypto instance for encryption)
        """
        key_material = os.urandom(30)  # 16 byte key + 14 byte salt
        key_b64 = base64.b64encode(key_material).decode('ascii')
        sdp_line = f"1 AES_CM_128_HMAC_SHA1_80 inline:{key_b64}"
        
        master_key = key_material[:16]
        master_salt = key_material[16:30]
        crypto = SRTPCrypto(master_key, master_salt)
        
        return sdp_line, crypto
    
    def _derive_session_key(self, label: int, index: int = 0) -> bytes:
        """Derive session key from master key using PRF.
        
        Args:
            label: Key derivation label (0x00=enc, 0x01=auth, 0x02=salt)
            index: Packet index (usually 0 for initial derivation)
            
        Returns:
            Derived session key
        """
        # Key derivation: AES-CM mode with master_key
        # Input: master_salt XOR (label || index || 0x00...)
        
        # Build IV for key derivation
        iv = bytearray(16)
        iv[0:14] = self.master_salt
        
        # XOR with label and index
        iv[7] ^= label
        
        # Encrypt zeros with AES-CM
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CTR(bytes(iv)),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Derive 16 bytes for encryption key, or 14 bytes for salt
        key_len = 16 if label in (0x00, 0x01) else 14
        session_key = encryptor.update(b'\x00' * key_len)
        
        return session_key
    
    def get_session_keys(self, ssrc: int) -> Tuple[bytes, bytes, bytes]:
        """Get or derive session keys for a given SSRC.
        
        Args:
            ssrc: RTP SSRC identifier
            
        Returns:
            (session_key, session_auth_key, session_salt)
        """
        if ssrc in self._session_keys:
            return self._session_keys[ssrc]
        
        # Derive keys for this SSRC
        session_key = self._derive_session_key(0x00)  # Encryption key
        session_auth_key = self._derive_session_key(0x01)  # Auth key
        session_salt = self._derive_session_key(0x02)  # Salt key
        
        keys = (session_key, session_auth_key, session_salt)
        self._session_keys[ssrc] = keys
        
        _LOGGER.debug(f"Derived session keys for SSRC {ssrc:08x}")
        
        return keys
    
    def decrypt_rtp(self, packet: bytes) -> Optional[bytes]:
        """Decrypt an SRTP packet to RTP.
        
        Args:
            packet: SRTP packet bytes (header + encrypted payload + auth tag)
            
        Returns:
            Decrypted RTP packet bytes, or None if decryption failed
        """
        try:
            # SRTP packet format:
            # [RTP Header (12+ bytes)] [Encrypted Payload] [Auth Tag (10 bytes)]
            
            if len(packet) < 12 + 10:  # Min header + auth tag
                _LOGGER.debug(f"Packet too short: {len(packet)} bytes")
                return None
            
            # Parse RTP header
            header = packet[:12]
            first_byte = header[0]
            cc = first_byte & 0x0F  # CSRC count
            
            # Calculate header length (skip CSRC if present)
            header_len = 12 + (cc * 4)
            
            if len(packet) < header_len + 10:
                _LOGGER.debug(f"Packet too short for header: {len(packet)} bytes")
                return None
            
            # Extract SSRC for key derivation
            ssrc = struct.unpack("!I", header[8:12])[0]
            
            # Get session keys
            session_key, session_auth_key, session_salt = self.get_session_keys(ssrc)
            
            # Extract auth tag (last 10 bytes for HMAC-SHA1-80)
            auth_tag = packet[-10:]
            srtp_packet = packet[:-10]  # Everything except auth tag
            
            # Verify authentication (optional but recommended)
            # For now, skip verification and just decrypt
            
            # Extract encrypted payload
            encrypted_payload = srtp_packet[header_len:]
            
            # Build IV for decryption
            # IV = session_salt XOR (SSRC || packet_index)
            sequence = struct.unpack("!H", header[2:4])[0]
            timestamp = struct.unpack("!I", header[4:8])[0]
            
            # Simplified: Use SSRC and sequence as IV
            iv = bytearray(16)
            iv[0:14] = session_salt
            iv[4:8] = header[8:12]  # SSRC
            iv[14:16] = header[2:4]  # Sequence
            
            # Decrypt using AES-CTR
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CTR(bytes(iv)),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_payload = decryptor.update(encrypted_payload)
            
            # Reconstruct RTP packet
            rtp_packet = header + decrypted_payload
            
            return rtp_packet
            
        except Exception as e:
            _LOGGER.error(f"SRTP decryption error: {e}")
            return None

    def encrypt_rtp(self, packet: bytes) -> Optional[bytes]:
        """Encrypt a plain RTP packet to SRTP.
        
        Args:
            packet: Plain RTP packet bytes (header + payload)
            
        Returns:
            SRTP packet bytes (header + encrypted payload + 10-byte auth tag), or None on error
        """
        try:
            if len(packet) < 12:
                return None
            
            # Parse RTP header
            header = packet[:12]
            first_byte = header[0]
            cc = first_byte & 0x0F
            header_len = 12 + (cc * 4)
            
            if len(packet) < header_len:
                return None
            
            # Extract SSRC for key derivation
            ssrc = struct.unpack("!I", header[8:12])[0]
            session_key, session_auth_key, session_salt = self.get_session_keys(ssrc)
            
            # Extract payload
            payload = packet[header_len:]
            
            # Build IV for encryption (same as decrypt — AES-CTR with SSRC + sequence)
            sequence = struct.unpack("!H", header[2:4])[0]
            iv = bytearray(16)
            iv[0:14] = session_salt
            iv[4:8] = header[8:12]   # SSRC
            iv[14:16] = header[2:4]  # Sequence
            
            # Encrypt using AES-CTR
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CTR(bytes(iv)),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_payload = encryptor.update(payload)
            
            # Build authenticated portion: header + encrypted_payload
            auth_portion = header + encrypted_payload
            
            # Compute HMAC-SHA1-80 authentication tag
            auth_tag = hmac.new(session_auth_key, auth_portion, hashlib.sha1).digest()[:10]
            
            return auth_portion + auth_tag
            
        except Exception as e:
            _LOGGER.error(f"SRTP encryption error: {e}")
            return None
