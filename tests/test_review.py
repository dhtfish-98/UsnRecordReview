import struct
import unittest
from usnrecordreview import inspect


def sample(v=2, usn=10):
    size = 64 if v == 2 else 80
    d = bytearray(size)
    struct.pack_into("<IHH", d, 0, size, v, 0)
    if v in (2, 3):
        at = 24 if v == 2 else 40
        fixed = 60 if v == 2 else 76
        struct.pack_into("<QQII", d, at, usn, 133000000000000000, 0x100, 0)
        struct.pack_into("<HH", d, fixed - 4, 2, fixed)
        d[fixed : fixed + 2] = b"x\0"
    elif v == 4:
        struct.pack_into("<QIIIHH", d, 40, usn, 1, 0, 0, 1, 16)
        struct.pack_into("<qq", d, 64, 100, 20)
    return bytes(d)


def extent_sample(count, usn=10):
    data = bytearray(sample(4, usn)[:64])
    struct.pack_into("<I", data, 0, 64 + 16 * count)
    struct.pack_into("<H", data, 60, count)
    data.extend(struct.pack("<qq", 0, 1) * count)
    return bytes(data)


class Tests(unittest.TestCase):
    def test_extent_budget_across_records(self):
        from unittest.mock import patch
        import usnrecordreview.core as core

        with patch.object(core, "MAX_RECORDS", 3):
            self.assertEqual(inspect(extent_sample(2) + extent_sample(1, 11))["status"], "PASS")
            report = inspect(extent_sample(2) + extent_sample(2, 11))
            self.assertIn("aggregate_extent_limit", report["findings"])
            self.assertEqual(report["status"], "FAIL")
    def test_versions(self):
        for v in (2, 3, 4):
            self.assertEqual(inspect(sample(v))["status"], "PASS")

    def test_multiple(self):
        self.assertEqual(inspect(sample() + sample(3, 11))["record_count"], 2)

    def test_order(self):
        self.assertEqual(inspect(sample(usn=11) + sample(usn=10))["status"], "FAIL")

    def test_zero_pages(self):
        self.assertEqual(inspect(b"\0" * 4096 + sample())["records"][0]["offset"], 4096)

    def test_padding(self):
        self.assertEqual(inspect(b"\0" * 4 + b"x" * 60)["status"], "FAIL")

    def test_unknown(self):
        self.assertEqual(inspect(sample(5))["status"], "OPEN")

    def test_truncated(self):
        d = sample(4)
        for i in range(len(d)):
            self.assertNotEqual(inspect(d[:i])["status"], "PASS")

    def test_bounds(self):
        d = bytearray(sample())
        struct.pack_into("<HH", d, 56, 2, 65534)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_continuation(self):
        d = bytearray(sample(4))
        struct.pack_into("<I", d, 56, 1)
        self.assertEqual(inspect(bytes(d))["status"], "OPEN")

    def test_empty(self):
        self.assertEqual(inspect(b"")["status"], "FAIL")

    def test_negative_usn(self):
        d = bytearray(sample())
        struct.pack_into("<q", d, 24, -1)
        self.assertEqual(inspect(bytes(d))["status"], "FAIL")

    def test_public_upstream_records(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        for v in (2, 4):
            r = inspect((root / f"examples/upstream_public_v{v}.bin").read_bytes())
            self.assertEqual(r["status"], "PASS")
            self.assertEqual(r["records"][0]["version"], v)
        self.assertEqual(
            inspect((root / "examples/upstream_public_v4.bin").read_bytes())["records"][
                0
            ]["extents"][0]["length"],
            0x284000,
        )
