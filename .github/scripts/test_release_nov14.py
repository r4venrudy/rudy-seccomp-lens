from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import release_checksums as guard


class ManifestBoundaryTests(unittest.TestCase):
    def stage(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        return Path(folder.name)

    def manifest(self, path, assets):
        (path / "SHA256SUMS").write_text(
            "".join(f"{sha256(data).hexdigest()}  {name}\n" for name, data in assets),
            encoding="ascii",
        )

    def prepare(self, name="demo.zip", data=b"fixture"):
        path = self.stage()
        (path / name).write_bytes(data)
        self.manifest(path, [(name, data)])
        return path

    def test_manifest_row_limit(self):
        path = self.prepare()
        with patch.object(guard, "MAX_MANIFEST_ROWS", 0, create=True):
            with self.assertRaisesRegex(ValueError, "manifest has too many rows"):
                guard.verify_checksums(path)

    def test_empty_asset(self):
        path = self.prepare(data=b"")
        with self.assertRaisesRegex(ValueError, "release archive is empty"):
            guard.verify_checksums(path)

    def test_manifest_filename_limit(self):
        path = self.prepare()
        with patch.object(guard, "MAX_ASSET_NAME", 7, create=True):
            with self.assertRaisesRegex(ValueError, "archive name is too long"):
                guard.verify_checksums(path)

    def test_manifest_rejects_device_names(self):
        path = self.stage()
        self.manifest(path, [("LPT2.zip", b"fixture")])
        with self.assertRaisesRegex(ValueError, "reserved Windows device"):
            guard.verify_checksums(path)

    def test_stage_entry_limit(self):
        path = self.prepare()
        (path / "extra.txt").write_bytes(b"sidecar")
        with patch.object(guard, "MAX_STAGE_ENTRIES", 2, create=True):
            with self.assertRaisesRegex(ValueError, "staging directory has too many entries"):
                guard.verify_checksums(path)
