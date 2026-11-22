from contextlib import redirect_stdout
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile
import release_guard as guard
import release_checksums as checksums

def package(names=("payload",)):
    output=BytesIO()
    with zipfile.ZipFile(output,"w") as archive:
        for name in names: archive.writestr(name,b"payload")
    return output.getvalue()

class ReleaseWorkBudgets(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder=Path(temporary.name)

    def verify(self,names):
        path=self.folder/"fixture.zip"
        path.write_bytes(package(names))
        return guard.verify(path)

    def main(self):
        with patch.object(sys,"argv",["release_guard.py",str(self.folder)]):
            with redirect_stdout(StringIO()): guard.main()

    def test_checksum_extension_case(self):
        for name in ("preview.ZIP","preview.JaR","preview.NUPKG","preview.WHL","preview.TAR.GZ","preview.TGZ","preview.TaR.Xz"):
            with self.subTest(name=name):
                path=self.folder/name
                path.write_bytes(b"payload")
                (self.folder/"SHA256SUMS.txt").write_text(sha256(b"payload").hexdigest()+"  "+name+"\n",encoding="ascii")
                checksums.verify_checksums(self.folder)
                path.unlink()
