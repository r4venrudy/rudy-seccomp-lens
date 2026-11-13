from io import BytesIO
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
import zipfile

from release_guard import verify


class PortablePathTests(unittest.TestCase):
    def check_zip(self, name):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "test.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, b"payload")
            return verify(path)

    def check_tar(self, name):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "test.tar.gz"
            with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(name)
                member.size = 7
                archive.addfile(member, BytesIO(b"payload"))
            return verify(path)

    def test_reserved_console_names(self):
        for check in (self.check_tar, self.check_zip):
            self.assertEqual(check("portable/console.txt"), (1, 7))
            for name in ("CONIN$", "nested/ConOut$.txt"):
                with self.assertRaisesRegex(ValueError, "nonportable Windows member name"):
                    check(name)

    def test_c1_control_names(self):
        for check in (self.check_tar, self.check_zip):
            self.assertEqual(check("data/\u00a1.txt"), (1, 7))
            for char in ("\u0080", "\u0085", "\u009f"):
                with self.assertRaisesRegex(ValueError, "unsafe release member name"):
                    check("data/a" + char + ".txt")

    def test_tar_filename_requires_unicode(self):
        self.assertEqual(self.check_tar("data/\u00ff.txt"), (1, 7))
        with self.assertRaisesRegex(ValueError, "invalid Unicode in release member name"):
            self.check_tar("data/\udcff.txt")
