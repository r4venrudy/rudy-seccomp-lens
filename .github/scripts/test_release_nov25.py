from contextlib import redirect_stdout,redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import hashlib,json,sys,unittest,zipfile
import release_checksums as checksums

class ChecksumCommandTests(unittest.TestCase):
    def setUp(self):
        folder=TemporaryDirectory();self.addCleanup(folder.cleanup);self.folder=Path(folder.name)
        self.archive=self.folder/'fixture.zip'
        with zipfile.ZipFile(self.archive,'w') as writer:writer.writestr('payload',b'content')
        self.manifest=self.folder/'SHA256SUMS.txt';self.refresh()
    def refresh(self):
        self.manifest.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest()+'  fixture.zip\n',encoding='ascii')
    def command(self,*args):
        out=StringIO()
        with patch.object(sys,'argv',['release_checksums.py',*map(str,args)]),redirect_stdout(out),redirect_stderr(StringIO()):
            checksums.main()
        return out.getvalue()

    def test_explicit_manifest(self):
        self.assertEqual(self.command(self.manifest),'Verified release SHA-256 manifest\n')
        self.assertEqual(self.command(self.folder),self.command(self.manifest))
        with self.assertRaises(SystemExit):self.command(self.archive)
        other=self.folder/'SHA256SUMS';other.write_bytes(self.manifest.read_bytes())
        with self.assertRaises(SystemExit):self.command(self.manifest)
