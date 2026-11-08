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
            commented_zip64 = zip64[:-2] + b"\x03\x00abc"
            for valid in (base, zip64, commented_zip64, b"prefix" + base, b"prefix" + zip64):
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

    def test_zip_stored_size(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "stored.zip"
            base = package()
            path.write_bytes(base)
            self.assertEqual(verify(path), (1, 150000))
            path.write_bytes(append_to_member(base, b"junk"))
            with self.assertRaisesRegex(ValueError, "stored ZIP member size"):
                verify(path)

    def test_zip_deflate_boundary(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "deflate.zip"
            base = package(zipfile.ZIP_DEFLATED)
            path.write_bytes(base)
            self.assertEqual(verify(path), (1, 150000))
            path.write_bytes(append_to_member(base, b"junk"))
            with self.assertRaisesRegex(ValueError, "DEFLATE stream"):
                verify(path)

            # A nonfinal stored block emits the entire declared file but has no end.
            with zipfile.ZipFile(io.BytesIO(base)) as archive:
                info = archive.infolist()[0]
            payload = b"abc" * 50000
            blocks = [payload[i:i + 60000] for i in range(0, len(payload), 60000)]
            unfinished = b"".join(
                b"\x00" + struct.pack("<HH", len(block), len(block) ^ 0xffff) + block
                for block in blocks
            )
            data = append_to_member(base, b"\0" * (len(unfinished) - info.compress_size))
            start = 30 + len(info.filename)
            data[start:start + len(unfinished)] = unfinished
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "DEFLATE stream"):
                verify(path)

    def test_staged_metadata_precedes_hashing(self):
        with TemporaryDirectory() as folder:
            stage = Path(folder)
            first = stage / "first.zip"
            first.write_bytes(b"first")
            later = stage / "later.zip"
            checksum = hashlib.sha256(b"first").hexdigest()
            (stage / "SHA256SUMS").write_text(
                f"{checksum}  first.zip\n{checksum}  later.zip\n", encoding="ascii")
            later.mkdir()
            real_open = Path.open

            def track_open(path, *args, **kwargs):
                if path == first:
                    self.fail("archive was opened before staged metadata was checked")
                return real_open(path, *args, **kwargs)

            with patch.object(Path, "open", track_open):
                with self.assertRaisesRegex(ValueError, "regular release archive for later"):
                    verify_checksums(stage)
                later.rmdir()
                later.write_bytes(b"first")
                with patch("release_checksums.MAX_CHECKSUM_TOTAL", 9):
                    with self.assertRaisesRegex(ValueError, "aggregate checksum limit"):
                        verify_checksums(stage)

    def test_dos_zip_directory_marker(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "dos.zip"
            for name in ("folder/", "folder"):
                member = zipfile.ZipInfo(name)
                member.create_system = 0
                member.external_attr = 0x10
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(member, b"")
                    archive.writestr("payload", b"abc")
                if name.endswith("/"):
                    self.assertEqual(verify(path), (2, 3))
                else:
                    with self.assertRaisesRegex(ValueError, "ZIP directory lacks a trailing slash"):
                        verify(path)
