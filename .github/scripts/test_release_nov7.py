import hashlib
import io
import lzma
from pathlib import Path
import struct
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from release_guard import verify
from release_checksums import verify_checksums


def basic_zip():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("payload", b"123")
    return output.getvalue()


class ReleaseBoundaryTests(unittest.TestCase):

    def test_zip_trailer_extent(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "footer.zip"
            base = basic_zip()
            for suffix in (b"trailing bytes", b"a"):
                path.write_bytes(base + suffix)
                with self.assertRaisesRegex(ValueError, "ZIP footer extent"):
                    verify(path)
            path.write_bytes(base[:-2] + b"\x03\0" + b"a")
            with self.assertRaisesRegex(ValueError, "ZIP footer extent"):
                verify(path)
            path.write_bytes(base[:-2] + b"\x03\0" + b"abc")
            self.assertEqual(verify(path), (1, 3))

    def test_zip_disk_and_entry_counts(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "counts.zip"
            base = basic_zip()
            for offset, value in ((4, 1), (6, 1), (8, 2)):
                data = bytearray(base)
                struct.pack_into("<H", data, len(base) - 22 + offset, value)
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "ZIP disk or entry count"):
                    verify(path)
            data = bytearray(base)
            struct.pack_into("<HH", data, len(base) - 14, 2, 2)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "ZIP directory entry count"):
                verify(path)

    def test_zip_directory_budget(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "budget.zip"
            path.write_bytes(basic_zip())
            import sys
            module = sys.modules.get("release_zip")
            if module is None:
                module = sys.modules["release_guard"]
            with patch.object(module, "MAX_DIRECTORY_BYTES", 16, create=True):
                with self.assertRaisesRegex(ValueError, "ZIP directory exceeds"):
                    verify(path)
            data = bytearray(path.read_bytes())
            struct.pack_into("<HH", data, len(data) - 14, 500, 500)
            path.write_bytes(data)
            with patch.object(module, "MAX_DIRECTORY_ENTRIES", 100, create=True):
                with self.assertRaisesRegex(ValueError, "ZIP directory exceeds"):
                    verify(path)

    def test_zip_data_descriptors(self):
        class NonSeekable(io.BytesIO):
            def seek(self, *args):
                raise OSError("stream only")
        with TemporaryDirectory() as folder:
            path = Path(folder) / "descriptor.zip"
            for wide in (False, True):
                output = NonSeekable()
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    with archive.open("streamed", "w", force_zip64=wide) as stream:
                        stream.write(b"payload")
                data = output.getvalue()
                descriptor = data.index(b"PK\x07\x08")
                central = data.index(b"PK\x01\x02")
                path.write_bytes(data)
                self.assertEqual(verify(path), (1, 7))
                unsigned = bytearray(data[:descriptor] + data[descriptor + 4:])
                struct.pack_into("<I", unsigned, len(unsigned) - 6, central - 4)
                path.write_bytes(unsigned)
                self.assertEqual(verify(path), (1, 7))
                damaged = bytearray(data)
                damaged[descriptor + 4] ^= 1
                path.write_bytes(damaged)
                with self.assertRaisesRegex(ValueError, "ZIP data descriptor"):
                    verify(path)

    def test_portable_component_byte_limit(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "components.zip"
            for component in ("a" * 256, "\u00e9" * 128):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("bin/" + component, b"x")
                with self.assertRaisesRegex(ValueError, "component exceeds"):
                    verify(path)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bin/" + "a" * 255, b"x")
            self.assertEqual(verify(path), (1, 1))
