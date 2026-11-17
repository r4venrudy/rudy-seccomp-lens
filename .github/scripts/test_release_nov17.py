from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import gzip
import stat
import tarfile
import unittest
import zipfile

from release_guard import verify


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)

    def tar(self, kind=tarfile.REGTYPE, mode=0o755, payload=b"fixture", dirty_padding=False):
        raw = BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("bin/example")
            member.type = kind
            member.mode = mode
            member.size = len(payload)
            archive.addfile(member, BytesIO(payload))
        data = bytearray(raw.getvalue())
        if dirty_padding:
            data[512 + len(payload)] = 1
        path = self.folder / "demo.tar.gz"
        path.write_bytes(gzip.compress(data))
        return verify(path)

    def zip(self, system, attributes):
        path = self.folder / "demo.zip"
        member = zipfile.ZipInfo("bin/example")
        member.create_system = system
        member.external_attr = attributes
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, b"fixture")
        return verify(path)

    def test_legacy_tar_type(self):
        self.assertEqual(self.tar(kind=tarfile.AREGTYPE), (1, 7))
        with self.assertRaisesRegex(ValueError, "unsupported TAR file type"):
            self.tar(kind=tarfile.CONTTYPE)

    def test_privileged_tar_modes(self):
        self.assertEqual(self.tar(mode=0o755), (1, 7))
        for permission in (stat.S_ISUID, stat.S_ISGID):
            with self.assertRaisesRegex(ValueError, "privileged TAR mode"):
                self.tar(mode=0o755 | permission)
