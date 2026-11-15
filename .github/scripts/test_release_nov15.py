from hashlib import sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import release_checksums as guard


class StagingTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.manifest = self.folder / "SHA256SUMS"
        self.asset = self.folder / "demo.zip"
        self.asset.write_bytes(b"contents")
        self.write_manifest([self.asset])

    def write_manifest(self, assets):
        self.manifest.write_text("".join(
            f"{sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n"
            for asset in assets), encoding="ascii")

    def copy(self, source):
        replacement = self.folder / "transient"
        replacement.write_bytes(source.read_bytes())
        return replacement

    def test_inventory_does_not_materialize_the_directory(self):
        with patch.object(Path, "iterdir", side_effect=AssertionError("eager directory listing")):
            guard.verify_checksums(self.folder)

    def test_manifest_requires_canonical_case(self):
        renamed = self.folder / "temporary-name"
        self.manifest.rename(renamed)
        renamed.rename(self.folder / "sha256sums")
        with self.assertRaisesRegex(ValueError, "manifest spelling"):
            guard.verify_checksums(self.folder)

    def test_manifest_replaced_before_open(self):
        replacement = self.copy(self.manifest)
        real_open = Path.open

        def open_file(path, *args, **kwargs):
            if path == self.manifest:
                replacement.replace(path)
            return real_open(path, *args, **kwargs)

        with patch.object(Path, "open", open_file):
            with self.assertRaisesRegex(ValueError, "manifest changed"):
                guard.verify_checksums(self.folder)
