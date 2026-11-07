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
