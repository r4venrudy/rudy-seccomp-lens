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

    def test_json_checksum_receipt(self):
        report=json.loads(self.command(self.manifest,'--json'))
        self.assertEqual(report['schema'],'rudy.release.checksum-report/v1')
        self.assertEqual(report['archive_count'],1)
        self.assertEqual(report['total_bytes'],self.archive.stat().st_size)
        self.assertEqual(report['manifest'],self.manifest.name)
        self.assertEqual(report['manifest_sha256'],hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(report['archives'],[dict(name='fixture.zip',bytes=self.archive.stat().st_size,sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest())])
        self.assertEqual(self.command(self.folder,'--json'),self.command(self.manifest,'--json'))
        self.archive.write_bytes(b'invalid')
        out=StringIO()
        with patch.object(sys,'argv',['release_checksums.py',str(self.folder),'--json']),redirect_stdout(out),redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):checksums.main()
        self.assertEqual(out.getvalue(),'')

    def test_checksum_budgets(self):
        size=self.archive.stat().st_size
        original=(checksums.MAX_ASSET,checksums.MAX_CHECKSUM_TOTAL)
        self.command(self.folder,'--max-asset-bytes',size,'--max-total-bytes',size)
        for flag,hard in (('--max-asset-bytes',original[0]),('--max-total-bytes',original[1])):
            for value in (0,-1,hard+1,size-1):
                with self.assertRaises(SystemExit):self.command(self.folder,flag,value)
            self.assertEqual((checksums.MAX_ASSET,checksums.MAX_CHECKSUM_TOTAL),original)
        with patch.object(Path,'open',side_effect=AssertionError('opened an oversized asset')):
            with self.assertRaises(SystemExit):self.command(self.folder,'--max-asset-bytes',0)

    def test_combined_archive_audit(self):
        report=json.loads(self.command(self.folder,'--json','--verify-archives'))
        self.assertTrue(report['archive_validation'])
        self.assertEqual((report['archives'][0]['entries'],report['archives'][0]['uncompressed_bytes']),(1,7))
        self.archive.write_bytes(b'not a zip');self.refresh()
        self.command(self.folder)
        with self.assertRaises(SystemExit):self.command(self.folder,'--verify-archives')
