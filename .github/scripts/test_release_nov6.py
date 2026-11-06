from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
import zipfile

from release_guard import verify


class ReleaseArchiveMetadataTests(unittest.TestCase):

    def test_archive_path_budget(self):
        with TemporaryDirectory() as scratch:
            archive = Path(scratch) / "paths.zip"
            for name in ("a" * 4097, "/".join(["a"] * 129)):
                with self.subTest(length=len(name)):
                    with zipfile.ZipFile(archive, "w") as writer:
                        writer.writestr(name, b"x")
                    with self.assertRaisesRegex(ValueError, "path budget"):
                        verify(archive)
