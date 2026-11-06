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

    def test_local_crc_and_sizes(self):
        with TemporaryDirectory() as scratch:
            archive = Path(scratch) / "metadata.zip"
            for offset in (14, 18, 22):
                with self.subTest(offset=offset):
                    with zipfile.ZipFile(archive, "w") as writer:
                        writer.writestr("payload.txt", b"payload")
                    data = bytearray(archive.read_bytes())
                    data[offset] ^= 1
                    archive.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "ZIP local CRC or size"):
                        verify(archive)
            with zipfile.ZipFile(archive, "w") as writer:
                with writer.open("forced64", "w", force_zip64=True) as stream:
                    stream.write(b"payload")
            self.assertEqual(verify(archive), (1, 7))
