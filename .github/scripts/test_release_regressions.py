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
