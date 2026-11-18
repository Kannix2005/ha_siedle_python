"""SRTP (AES_CM_128_HMAC_SHA1_80) against the published test vectors."""
import importlib
import base64
import unittest

import test_sip_forwarding  # registers the siedle_ut package

try:
    srtp = importlib.import_module("siedle_ut.srtp_handler")
except ImportError:  # cryptography not installed
    srtp = None

MASTER_KEY = bytes.fromhex("E1F97A0D3E018BE0D64FA32C06DE4139")
MASTER_SALT = bytes.fromhex("0EC675AD498AFEEBB6960B3AABE6")
# libsrtp's srtp_validate() reference packet for the same master key and salt
PLAIN = bytes.fromhex("800f1234decafbadcafebabe" + "ab" * 16)
CIPHER = bytes.fromhex(
    "800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402b78d6acc99ea179b8dbb")


@unittest.skipIf(srtp is None, "cryptography not installed")
class SrtpVectorTest(unittest.TestCase):
    def setUp(self):
        self.ctx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)

    def test_session_keys_match_rfc3711_appendix_b3(self):
        key, auth, salt = self.ctx.get_session_keys(0xCAFEBABE)
        self.assertEqual(key.hex().upper(), "C61E7A93744F39EE10734AFE3FF7A087")
        self.assertEqual(salt.hex().upper(), "30CBBC08863D8C85D49DB34A9AE1")
        self.assertEqual(auth.hex().upper(), "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4")

    def test_encrypt_matches_reference_packet(self):
        self.assertEqual(self.ctx.encrypt_rtp(PLAIN).hex(), CIPHER.hex())

    def test_decrypt_matches_reference_packet(self):
        self.assertEqual(self.ctx.decrypt_rtp(CIPHER), PLAIN)
        self.assertTrue(self.ctx._auth_verified_once)

    def test_tampered_packet_is_dropped_once_a_tag_verified(self):
        self.ctx.decrypt_rtp(CIPHER)
        forged = bytearray(CIPHER)
        forged[20] ^= 0xFF
        self.assertIsNone(self.ctx.decrypt_rtp(bytes(forged)))

    def test_roundtrip_survives_sequence_rollover(self):
        tx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        rx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        for seq in (65534, 65535, 0, 1):
            packet = bytes.fromhex("8008") + seq.to_bytes(2, "big") + bytes(4) + b"\x11\x22\x33\x44" + b"audio" * 4
            self.assertEqual(rx.decrypt_rtp(tx.encrypt_rtp(packet)), packet)
        self.assertTrue(rx._auth_verified_once)

    @staticmethod
    def _packet(seq):
        return bytes.fromhex("8008") + seq.to_bytes(2, "big") + bytes(4) + b"\x11\x22\x33\x44" + b"audio" * 4

    def test_reordered_packet_across_the_rollover(self):
        # Sender order 65534, 65535, 0, 1 — 65534 arrives late, after the wrap.
        tx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        rx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        sent = {seq: tx.encrypt_rtp(self._packet(seq)) for seq in (65534, 65535, 0, 1, 2)}
        for seq in (65535, 0, 65534, 1, 2):
            self.assertEqual(rx.decrypt_rtp(sent[seq]), self._packet(seq), seq)

    def test_forged_packets_cannot_move_the_rollover_counter(self):
        tx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        rx = srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT)
        self.assertIsNotNone(rx.decrypt_rtp(tx.encrypt_rtp(self._packet(40000))))
        for seq in (100, 30000, 50000, 100):
            forged = self._packet(seq) + b"\x00" * 10  # no valid tag
            self.assertIsNone(rx.decrypt_rtp(forged))
        self.assertEqual(rx.decrypt_rtp(tx.encrypt_rtp(self._packet(40001))), self._packet(40001))

    def test_header_extension_stays_in_the_clear(self):
        header = bytes.fromhex("9008000100000000aabbccdd") + bytes.fromhex("bede0001") + b"\x01\x02\x03\x04"
        packet = header + b"payload-bytes"
        out = self.ctx.encrypt_rtp(packet)
        self.assertEqual(out[:len(header)], header)
        self.assertEqual(srtp.SRTPCrypto(MASTER_KEY, MASTER_SALT).decrypt_rtp(out), packet)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(srtp is None, "cryptography not installed")
class OfferSelectionTest(unittest.TestCase):
    """#28: answer the audio crypto line that was offered, with its tag."""

    KEY = base64.b64encode(bytes(range(30))).decode()

    def offer(self, *lines):
        return "\r\n".join(("v=0", *lines, ""))

    def test_audio_line_with_supported_suite_wins(self):
        sdp = self.offer(
            "m=video 5004 RTP/SAVP 96",
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{self.KEY}",
            "m=audio 5002 RTP/SAVP 8",
            f"a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:{self.KEY}",
            f"a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{self.KEY}|2^31|1:1",
        )
        tag, line = srtp.SRTPCrypto.select_offer_crypto(sdp)
        self.assertEqual(tag, "2")
        self.assertIn("|2^31|1:1", line)

    def test_offer_without_supported_audio_suite_is_not_taken(self):
        sdp = self.offer("m=audio 5002 RTP/SAVP 8",
                         f"a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:{self.KEY}")
        self.assertIsNone(srtp.SRTPCrypto.select_offer_crypto(sdp))

    def test_lifetime_and_mki_are_not_part_of_the_key(self):
        crypto = srtp.SRTPCrypto.from_base64(
            f"2 AES_CM_128_HMAC_SHA1_80 inline:{self.KEY}|2^31|1:1")
        self.assertEqual(crypto.master_key, bytes(range(16)))
        self.assertEqual(crypto.master_salt, bytes(range(16, 30)))

    def test_answer_echoes_the_tag(self):
        line, _ = srtp.SRTPCrypto.generate_sdp_crypto_line("2")
        self.assertTrue(line.startswith("2 AES_CM_128_HMAC_SHA1_80 inline:"))
