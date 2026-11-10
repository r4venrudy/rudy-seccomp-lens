import io
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
import zipfile

from release_guard import verify


def fixture(extra):
    member = zipfile.ZipInfo("note")
    member.extra = extra
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, b"abc")
    return bytearray(buffer.getvalue())


class ZipExtraFieldTests(unittest.TestCase):
    def verify(self, data):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.zip"
            path.write_bytes(data)
            return verify(path)

    def test_local_extra_framing(self):
        base = fixture(struct.pack("<HHB", 0xcafe, 1, 42))
        self.assertEqual(self.verify(base), (1, 3))
        for length in (0, 2):
            data = bytearray(base)
            struct.pack_into("<H", data, 30 + len("note") + 2, length)
            with self.assertRaisesRegex(ValueError, "local ZIP extra field"):
                self.verify(data)

    def test_central_extra_framing(self):
        base = fixture(struct.pack("<HHB", 0xcafe, 1, 42))
        self.assertEqual(self.verify(base), (1, 3))
        central = base.index(b"PK\x01\x02")
        struct.pack_into("<H", base, central + 46 + len("note") + 2, 0)
        with self.assertRaisesRegex(ValueError, "central ZIP extra field"):
            self.verify(base)

    def test_repeated_structural_extra_fields(self):
        from binascii import crc32
        def field(kind, content):
            return struct.pack("<HH", kind, len(content)) + content

        self.assertEqual(self.verify(fixture(field(0xcafe, b"") * 2)), (1, 3))
        self.assertEqual(self.verify(fixture(field(1, b""))), (1, 3))
        for kind in (1, 0x7075):
            value = b"" if kind == 1 else struct.pack("<BI", 1, crc32(b"note")) + b"note"
            base = fixture(field(0xcafe, value) * 2)
            central = base.index(b"PK\x01\x02")
            for offset in (30 + len("note"), central + 46 + len("note")):
                data = bytearray(base)
                struct.pack_into("<H", data, offset, kind)
                struct.pack_into("<H", data, offset + 4 + len(value), kind)
                with self.assertRaisesRegex(ValueError, "duplicate .*ZIP extra field"):
                    self.verify(data)
