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
