from io import BytesIO
import gzip
import struct
import zlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import BadZipFile, ZipFile, ZipInfo
from unittest.mock import patch
import release_guard as guard

def unicode_path(name, alias):
    body = b"\x01" + struct.pack("<I", zlib.crc32(name)) + alias
    return struct.pack("<HH", 0x7075, len(body)) + body

class ReleaseInteroperability(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)

    def zip_bytes(self, extra=b"", force64=False):
        stream = BytesIO()
        with ZipFile(stream, "w") as archive:
            info = ZipInfo("safe.txt")
            info.extra = extra
            if force64:
                with archive.open(info, "w", force_zip64=True) as entry:
                    entry.write(b"payload")
            else:
                archive.writestr(info, b"payload")
        return bytearray(stream.getvalue())

    def verify_zip(self, data):
        file = self.folder / "fixture.zip"
        file.write_bytes(data)
        return guard.verify(file)

    def fhcrc(self, valid=True):
        packed = gzip.compress(bytes(2048))
        header = packed[:3] + b"\x02" + packed[4:10]
        crc = zlib.crc32(header) & 0xffff
        return header + struct.pack("<H", crc if valid else crc ^ 1) + packed[10:]

    def test_central_unicode_alias(self):
        for alias in (b"../escape", b"different", b"safe.txt\0hidden", b"\xff"):
            data = self.zip_bytes(unicode_path(b"safe.txt", alias))
            # Keep the local override harmless so this isolates central metadata.
            local_size = struct.unpack_from("<H", data, 28)[0]
            data[30 + 8:30 + 8 + local_size] = b"\x00\x00" + struct.pack("<H", local_size - 4) + bytes(local_size - 4)
            with self.assertRaises((ValueError, BadZipFile)):
                self.verify_zip(data)
        self.assertEqual(self.verify_zip(self.zip_bytes(unicode_path(b"safe.txt", b"safe.txt"))), (1, 7))
        for extra in (struct.pack("<HH", 0x7075, 0), unicode_path(b"wrong", b"safe.txt")):
            with self.assertRaises((ValueError, BadZipFile)):
                self.verify_zip(self.zip_bytes(extra))

    def test_local_unicode_alias(self):
        for alias in (b"../escape", b"different", b"\xff"):
            data = self.zip_bytes(unicode_path(b"safe.txt", alias))
            central = data.index(b"PK\x01\x02")
            extra_size = struct.unpack_from("<H", data, central + 30)[0]
            offset = central + 46 + 8
            data[offset:offset + extra_size] = b"\x00\x00" + struct.pack("<H", extra_size - 4) + bytes(extra_size - 4)
            with self.assertRaises((ValueError, BadZipFile)):
                self.verify_zip(data)

    def test_zip64_feature_version(self):
        data = self.zip_bytes(force64=True)
        self.assertEqual(self.verify_zip(data), (1, 7))
        for local, central in ((20, 45), (45, 20), (20, 20)):
            changed = bytearray(data)
            changed[4] = local
            changed[changed.index(b"PK\x01\x02") + 6] = central
            with self.assertRaisesRegex(ValueError, "ZIP64 extraction version"):
                self.verify_zip(changed)
