import hashlib
from pathlib import Path
import tempfile
import unittest

from release_checksums import verify_checksums


class ReleaseChecksumsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.asset = self.directory / "demo.zip"
        self.asset.write_bytes(b"package bytes")
        self.manifest = self.directory / "SHA256SUMS.txt"
        self.row = hashlib.sha256(b"package bytes").hexdigest() + "  demo.zip"
        self.manifest.write_bytes((self.row + "\r\n").encode("ascii"))

    def test_accepts_portable_checksum_rows(self):
        verify_checksums(self.directory)
        self.manifest.write_text(self.row.upper()[:64] + " *demo.zip\n", encoding="ascii")
        verify_checksums(self.directory)

    def test_rejects_changed_bytes(self):
        self.asset.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_checksums(self.directory)

    def test_rejects_path_qualified_rows(self):
        self.manifest.write_text(self.row.replace("demo.zip", "../demo.zip"), encoding="ascii")
        with self.assertRaisesRegex(ValueError, "row"):
            verify_checksums(self.directory)

    def test_rejects_duplicate_rows(self):
        self.manifest.write_text(self.row + "\n" + self.row + "\n", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_checksums(self.directory)

    def test_rejects_missing_asset(self):
        self.asset.unlink()
        with self.assertRaisesRegex(ValueError, "regular release archive"):
            verify_checksums(self.directory)

    def test_rejects_multiple_manifests(self):
        (self.directory / "SHA256SUMS").touch()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            verify_checksums(self.directory)

    def test_rejects_unlisted_archives(self):
        for name in ("extra.zip", "extra.ZIP", "extra.nupkg", "extra.tar.gz"):
            with self.subTest(name=name):
                extra = self.directory / name
                extra.touch()
                try:
                    with self.assertRaisesRegex(ValueError, "unlisted release archives"):
                        verify_checksums(self.directory)
                finally:
                    extra.unlink()

    def test_ignores_non_archive_checksum_sidecars(self):
        (self.directory / "demo.zip.sha256").write_text(self.row, encoding="ascii")
        verify_checksums(self.directory)
