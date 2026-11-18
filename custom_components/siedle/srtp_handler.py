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


# Crypto suites this module implements (RFC 4568 names).
SUPPORTED_SUITES = ("AES_CM_128_HMAC_SHA1_80",)

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
        self._session_keys: Tuple[bytes, bytes, bytes] = ()
        # Rollover counter per SSRC, keeps the CTR keystream unique past the
        # 16-bit sequence wrap.
        self._roc_state: dict = {}
        # Integrity checking is enforced from the first tag that verifies.
        self._auth_verified_once = False
        self._auth_warned = False

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
            
            # inline:<key||salt>[|lifetime][|MKI:length] [session params]
            key_material_b64 = crypto_suite.split("inline:", 1)[1].strip()
            key_material_b64 = key_material_b64.split()[0].split("|")[0]
            key_material = base64.b64decode(key_material_b64, validate=True)
            
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
    def select_offer_crypto(sdp: str) -> Optional[Tuple[str, str]]:
        """Pick the a=crypto line of the audio stream we can handle.

        Returns (tag, attribute value) or None. Only the audio m-section is
        looked at (an offer may carry video with its own keys), and only
        AES_CM_128_HMAC_SHA1_80, the one suite this module implements. The
        old code took the first a=crypto line of the whole body, whatever
        its suite or media line.
        """
        in_audio = False
        for line in sdp.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if line.startswith("m="):
                in_audio = line.startswith("m=audio")
                continue
            if not in_audio or not line.startswith("a=crypto:"):
                continue
            value = line[len("a=crypto:"):]
            parts = value.split()
            if len(parts) >= 3 and parts[1] in SUPPORTED_SUITES:
                return parts[0], value
        return None

    @staticmethod
    def generate_sdp_crypto_line(tag: str = "1") -> Tuple[str, "SRTPCrypto"]:
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
        # RFC 4568 6.1: the answer echoes the tag of the offer line it accepts.
        sdp_line = f"{tag} AES_CM_128_HMAC_SHA1_80 inline:{key_b64}"
        
        master_key = key_material[:16]
        master_salt = key_material[16:30]
        crypto = SRTPCrypto(master_key, master_salt)
        
        return sdp_line, crypto
    
    # Lengths of the derived session keys by label (RFC 3711 §4.3, §5.2):
    # cipher key 128 bit, HMAC-SHA1 key 160 bit, cipher salt 112 bit.
    _KEY_LENGTHS = {0x00: 16, 0x01: 20, 0x02: 14}

    def _derive_session_key(self, label: int) -> bytes:
        """Derive a session key from the master key (RFC 3711 §4.3.1).

        Key derivation rate 0: AES-CM keystream with the IV
        (master_salt XOR label * 2^48) * 2^16.
        """
        iv = bytearray(16)
        iv[0:14] = self.master_salt
        iv[7] ^= label
        encryptor = Cipher(
            algorithms.AES(self.master_key),
            modes.CTR(bytes(iv)),
            backend=default_backend()
        ).encryptor()
        return encryptor.update(b'\x00' * self._KEY_LENGTHS[label])

    def get_session_keys(self, ssrc: int) -> Tuple[bytes, bytes, bytes]:
        """Return (cipher key, auth key, cipher salt).

        They depend on the master key only; `ssrc` is kept for callers.
        """
        if not self._session_keys:
            self._session_keys = (
                self._derive_session_key(0x00),
                self._derive_session_key(0x01),
                self._derive_session_key(0x02),
            )
            _LOGGER.debug("Derived SRTP session keys")
        return self._session_keys

    @staticmethod
    def _header_length(packet: bytes) -> int:
        """Length of the RTP header including CSRCs and header extension."""
        length = 12 + (packet[0] & 0x0F) * 4
        if packet[0] & 0x10 and len(packet) >= length + 4:
            length += 4 + struct.unpack("!H", packet[length + 2:length + 4])[0] * 4
        return length

    def _estimate_roc(self, ssrc: int, sequence: int) -> int:
        """Rollover counter for this packet (RFC 3711 §3.3.1, Appendix A).

        Only estimates. _commit_roc() stores the result once the packet is
        accepted, so a forged or late packet cannot move the counter.
        """
        state = self._roc_state.get(ssrc)
        if state is None:
            return 0
        roc, last = state
        if last < 32768:
            if sequence - last > 32768:
                return (roc - 1) & 0xFFFFFFFF if roc else 0
        elif last - 32768 > sequence:
            return (roc + 1) & 0xFFFFFFFF
        return roc

    def _commit_roc(self, ssrc: int, roc: int, sequence: int) -> None:
        """Remember the highest packet index seen for this source."""
        state = self._roc_state.get(ssrc)
        if state is None or (roc, sequence) > state or (state[0] == 0xFFFFFFFF and roc == 0):
            self._roc_state[ssrc] = (roc, sequence)

    @staticmethod
    def _build_iv(session_salt: bytes, ssrc: int, roc: int, sequence: int) -> bytes:
        """AES-CM IV (RFC 3711 §4.1.1).

        (salt * 2^16) XOR (SSRC * 2^64) XOR (packet index * 2^16), where the
        packet index is ROC || SEQ; the low 16 bits are the block counter.
        """
        value = (
            (int.from_bytes(session_salt, "big") << 16)
            ^ (ssrc << 64)
            ^ (((roc << 16) | sequence) << 16)
        )
        return value.to_bytes(16, "big")

    @staticmethod
    def _auth_tag(auth_key: bytes, authenticated: bytes, roc: int) -> bytes:
        """HMAC-SHA1 over the packet and the ROC, cut to 80 bits (§4.2)."""
        return hmac.new(auth_key, authenticated + struct.pack("!I", roc), hashlib.sha1).digest()[:10]

    def decrypt_rtp(self, packet: bytes) -> Optional[bytes]:
        """Decrypt an SRTP packet to RTP.

        Returns the RTP packet, or None if it is malformed or fails the
        integrity check.
        """
        try:
            if len(packet) < 12 + 10:
                _LOGGER.debug(f"Packet too short: {len(packet)} bytes")
                return None
            header_len = self._header_length(packet)
            if len(packet) < header_len + 10:
                _LOGGER.debug(f"Packet too short for header: {len(packet)} bytes")
                return None

            sequence, ssrc = struct.unpack("!H4xI", packet[2:12])
            session_key, session_auth_key, session_salt = self.get_session_keys(ssrc)
            roc = self._estimate_roc(ssrc, sequence)

            auth_tag = packet[-10:]
            srtp_packet = packet[:-10]
            if hmac.compare_digest(self._auth_tag(session_auth_key, srtp_packet, roc), auth_tag):
                if not self._auth_verified_once:
                    _LOGGER.info("SRTP: auth tag verified, integrity checking active")
                self._auth_verified_once = True
            elif self._auth_verified_once:
                # We know this peer's tags normally verify, so this packet is
                # forged or corrupted.
                _LOGGER.warning("SRTP: dropping packet with invalid auth tag")
                return None
            elif not self._auth_warned:
                # Never saw a valid tag yet. Don't cut the audio over it, but
                # say so once — integrity is not enforced in this state.
                self._auth_warned = True
                _LOGGER.warning(
                    "SRTP: auth tag does not verify; continuing without integrity "
                    "checking until a valid tag is seen"
                )

            # Accepted: only now may the packet advance the rollover state.
            self._commit_roc(ssrc, roc, sequence)

            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.CTR(self._build_iv(session_salt, ssrc, roc, sequence)),
                backend=default_backend()
            ).decryptor()
            return srtp_packet[:header_len] + decryptor.update(srtp_packet[header_len:])

        except Exception as e:
            _LOGGER.error(f"SRTP decryption error: {e}")
            return None

    def encrypt_rtp(self, packet: bytes) -> Optional[bytes]:
        """Encrypt a plain RTP packet to SRTP (payload encrypted, 10-byte tag appended)."""
        try:
            if len(packet) < 12:
                return None
            header_len = self._header_length(packet)
            if len(packet) < header_len:
                return None

            sequence, ssrc = struct.unpack("!H4xI", packet[2:12])
            session_key, session_auth_key, session_salt = self.get_session_keys(ssrc)
            roc = self._estimate_roc(ssrc, sequence)
            self._commit_roc(ssrc, roc, sequence)

            encryptor = Cipher(
                algorithms.AES(session_key),
                modes.CTR(self._build_iv(session_salt, ssrc, roc, sequence)),
                backend=default_backend()
            ).encryptor()
            auth_portion = packet[:header_len] + encryptor.update(packet[header_len:])
            return auth_portion + self._auth_tag(session_auth_key, auth_portion, roc)

        except Exception as e:
            _LOGGER.error(f"SRTP encryption error: {e}")
            return None
