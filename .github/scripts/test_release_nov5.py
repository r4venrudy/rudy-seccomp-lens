import hashlib
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from release_guard import verify
from release_checksums import verify_checksums


class ReleasePortabilityRegressions(unittest.TestCase):

    def test_windows_namespace_portability(self):
        with TemporaryDirectory() as scratch:
            archive = Path(scratch) / "portable.zip"
            names = ["file" + c + ".txt" for c in '<>"|?*']
            names += ["COM\u00b9.txt", "lpt\u00b2/log", "bin/LPT\u00b3"]
            for name in names:
                with self.subTest(name=name):
                    with zipfile.ZipFile(archive, "w") as writer:
                        writer.writestr(name, b"payload")
                    with self.assertRaisesRegex(ValueError, "Windows"):
                        verify(archive)

    def test_zip_local_metadata_matches_central(self):
        with TemporaryDirectory() as scratch:
            archive = Path(scratch) / "metadata.zip"
            for offset, changed in ((6, 0x800), (8, 8)):
                with self.subTest(offset=offset):
                    with zipfile.ZipFile(archive, "w") as writer:
                        writer.writestr("file.txt", b"payload")
                    data = bytearray(archive.read_bytes())
                    struct.pack_into("<H", data, offset, changed)
                    archive.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "ZIP local metadata"):
                        verify(archive)
