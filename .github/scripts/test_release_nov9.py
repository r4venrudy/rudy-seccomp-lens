import io
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

import release_guard


def fixture(compression=zipfile.ZIP_STORED, streamed=False):
    class StreamOnly(io.BytesIO):
        def seek(self, *args):
            raise OSError("stream only")

    buffer = StreamOnly() if streamed else io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr("first", b"abc")
        archive.writestr("second", b"def")
    return buffer.getvalue()


class ReleaseInventoryTests(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "members.zip"

    def verify(self, data):
        self.path.write_bytes(data)
        return release_guard.verify(self.path)

    def test_member_disk(self):
        data = bytearray(fixture())
        self.assertEqual(self.verify(data), (2, 6))
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 34, 1)
        with self.assertRaisesRegex(ValueError, "another disk"):
            self.verify(data)

    def test_zip_encryption_flags(self):
        for flag in (1 << 13, 1 << 6, 1):
            data = bytearray(fixture())
            central = data.index(b"PK\x01\x02")
            struct.pack_into("<H", data, 6, flag)
            struct.pack_into("<H", data, central + 8, flag)
            with self.assertRaisesRegex(ValueError, "encrypted release member"):
                self.verify(data)

    def test_bounded_release_zip_methods(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            self.assertEqual(self.verify(fixture(method)), (2, 6))
        for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.assertRaisesRegex(ValueError, "unsupported release ZIP compression"):
                self.verify(fixture(method))

    def test_streamed_local_fields(self):
        data = fixture(streamed=True)
        self.assertEqual(self.verify(data), (2, 6))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member = archive.infolist()[0]
        populated = bytearray(data)
        struct.pack_into("<III", populated, 14, member.CRC, member.compress_size, member.file_size)
        self.assertEqual(self.verify(populated), (2, 6))
        for offset in (14, 18, 22):
            invalid = bytearray(data)
            struct.pack_into("<I", invalid, offset, 2)
            with self.assertRaisesRegex(ValueError, "streamed ZIP local fields"):
                self.verify(invalid)

    def test_zip_budget_before_member_open(self):
        data = fixture()
        self.assertEqual(self.verify(data), (2, 6))
        for budget, limit in (("MAX_MEMBER", 2), ("MAX_TOTAL", 5)):
            with patch.object(release_guard, budget, limit):
                with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("opened before ZIP budget")):
                    with self.assertRaisesRegex(ValueError, "resource limits"):
                        self.verify(data)
