import hashlib
import io
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from release_checksums import verify_checksums
from release_guard import verify
import release_zip


def package(method=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=method) as archive:
        archive.writestr("payload", b"abc" * 50000)
    return buffer.getvalue()


def append_to_member(base, extra):
    data = bytearray(base)
    directory = data.index(b"PK\x01\x02")
    packed, = struct.unpack_from("<I", data, 18)
    struct.pack_into("<I", data, 18, packed + len(extra))
    struct.pack_into("<I", data, directory + 20, packed + len(extra))
    struct.pack_into("<I", data, len(data) - 6, directory + len(extra))
    data[directory:directory] = extra
    return data


class ReleaseStructureTests(unittest.TestCase):

    def test_zip_directory_structure_before_member_allocation(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "directory.zip"
            base = package()
            with patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 0):
                zip64 = package()
            self.assertIn(b"PK\x06\x06", zip64)
            for valid in (base, zip64, b"prefix" + base, b"prefix" + zip64):
                path.write_bytes(valid)
                self.assertEqual(verify(path), (1, 150000))
            count = bytearray(base)
            struct.pack_into("<HH", count, len(count) - 14, 0, 0)
            span = bytearray(base)
            struct.pack_into("<H", span, span.index(b"PK\x01\x02") + 30, 65535)
            for data in (count, span):
                path.write_bytes(data)
                with patch.object(zipfile, "ZipFile", wraps=zipfile.ZipFile) as constructor:
                    with self.assertRaises((ValueError, zipfile.BadZipFile)):
                        verify(path)
                    constructor.assert_not_called()
