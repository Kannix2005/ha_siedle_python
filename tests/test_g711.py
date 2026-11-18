"""G.711 decoding used for recordings and level diagnostics."""
import importlib
import struct
import unittest

import test_sip_forwarding  # registers the siedle_ut package


def _rtp():
    return importlib.import_module("siedle_ut.rtp_handler")


def _samples(pcm: bytes):
    return list(struct.unpack(f"<{len(pcm) // 2}h", pcm))


class G711DecodeTest(unittest.TestCase):
    def test_alaw_reference_values(self):
        # ITU-T G.711: 0xD5/0x55 are the smallest steps, 0xAA/0x2A full scale.
        self.assertEqual(
            _samples(_rtp().pcma_to_linear(bytes([0xD5, 0x55, 0xAA, 0x2A]))),
            [8, -8, 32256, -32256],
        )

    def test_ulaw_reference_values(self):
        self.assertEqual(
            _samples(_rtp().pcmu_to_linear(bytes([0xFF, 0x7F, 0x80, 0x00]))),
            [0, 0, 32124, -32124],
        )

    def test_peak_level_tells_silence_from_noise(self):
        rtp = _rtp()
        self.assertLess(rtp.peak_level(8, bytes([0xD5]) * 160), 100)
        self.assertGreater(rtp.peak_level(8, bytes(range(256))), 30000)
        self.assertEqual(rtp.peak_level(101, b"\x01\x02\x03\x04"), 0)


if __name__ == "__main__":
    unittest.main()


rh = _rtp()


class GainTest(unittest.TestCase):
    """#35: optional gain per direction on G.711 payloads."""

    def levels(self, payload_type, payload):
        pcm = rh.pcma_to_linear(payload) if payload_type == 8 else rh.pcmu_to_linear(payload)
        return [v for (v,) in struct.iter_unpack("<h", pcm)]

    def test_zero_gain_needs_no_table(self):
        self.assertIsNone(rh.build_gain_table(8, 0))
        self.assertIsNone(rh.build_gain_table(101, 6))

    def test_six_db_doubles_quiet_samples_and_keeps_the_sign(self):
        codes = bytes(range(256))
        for pt in (0, 8):
            before = self.levels(pt, codes)
            after = self.levels(pt, codes.translate(rh.build_gain_table(pt, 6)))
            for b, a in zip(before, after):
                self.assertTrue(a == 0 or (a > 0) == (b > 0) or b == 0)
                if 200 < abs(b) < 8000:
                    self.assertAlmostEqual(abs(a) / abs(b), 2.0, delta=0.15)

    def test_loud_samples_are_limited_not_wrapped(self):
        codes = bytes(range(256))
        before = self.levels(8, codes)
        after = self.levels(8, codes.translate(rh.build_gain_table(8, 18)))
        for b, a in zip(before, after):
            self.assertGreaterEqual(abs(a), abs(b))  # never quieter, never flipped
            self.assertLessEqual(abs(a), 32767)

    def test_bridge_changes_the_payload_and_keeps_the_header(self):
        packet = rh.RtpPacket(version=2, padding=False, extension=False, cc=0, marker=False,
                              payload_type=8, sequence=7, timestamp=160, ssrc=1,
                              payload=bytes([0xD5, 0x95, 0x15] * 50))
        raw = packet.serialize() if hasattr(packet, "serialize") else packet.to_bytes()
        bridge = rh.RtpBridge()
        bridge.set_gains(door_to_phone_db=6)
        out = rh.apply_gain(raw, packet, bridge._gain_tables_a_to_b)
        self.assertEqual(out[:12], raw[:12])
        self.assertNotEqual(out[12:], raw[12:])
        self.assertEqual(rh.apply_gain(raw, packet, bridge._gain_tables_b_to_a), raw)
