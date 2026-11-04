import gzip
import hashlib
from pathlib import Path
import stat
import tarfile
from tempfile import TemporaryDirectory
import unittest
import zipfile

import release_checksums
from release_checksums import verify_checksums
from release_guard import verify


class ReleaseContractRegressions(unittest.TestCase):
    def test_manifest_control_delimiter(self):
        with TemporaryDirectory() as scratch:
            folder = Path(scratch)
            for name in ("a.zip", "b.zip"):
                (folder / name).write_bytes(b"x")
            digest = hashlib.sha256(b"x").hexdigest()
            (folder / "SHA256SUMS").write_bytes(f"{digest}  a.zip\v{digest}  b.zip\n".encode())
            with self.assertRaisesRegex(ValueError, "manifest row"):
                verify_checksums(folder)
    def test_checksum_work_budget(self):
        from unittest.mock import patch
        with TemporaryDirectory() as scratch:
            folder = Path(scratch)
            digest = hashlib.sha256(b"1234").hexdigest()
            for name in ("a.zip", "b.zip"):
                (folder / name).write_bytes(b"1234")
            (folder / "SHA256SUMS").write_text(f"{digest}  a.zip\n{digest}  b.zip\n")
            with patch.object(release_checksums, "MAX_CHECKSUM_TOTAL", 7, create=True):
                with self.assertRaisesRegex(ValueError, "aggregate checksum"):
                    verify_checksums(folder)
    def test_implicit_directory_aliases(self):
        with TemporaryDirectory() as scratch:
            path = Path(scratch) / "aliases.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Bin/first", b"1")
                archive.writestr("bin/second", b"2")
            with self.assertRaisesRegex(ValueError, "prefix spellings"):
                verify(path)
    def test_zip_directory_contract(self):
        with TemporaryDirectory() as scratch:
            for name, mode, payload in [("dir/", stat.S_IFDIR, b"x"),
                                        ("dir/", stat.S_IFREG, b""),
                                        ("dir", stat.S_IFDIR, b"")]:
                with self.subTest(name=name, mode=mode, payload=payload):
                    path = Path(scratch) / "directory.zip"
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = (mode | 0o755) << 16
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr(entry, payload)
                        archive.writestr("file", b"x")
                    with self.assertRaisesRegex(ValueError, "ZIP directory"):
                        verify(path)
