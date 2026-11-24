from contextlib import redirect_stdout,redirect_stderr
from io import StringIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile
import release_guard as guard

class ReleaseCommandTests(unittest.TestCase):
    def setUp(self):
        folder=TemporaryDirectory();self.addCleanup(folder.cleanup);self.folder=Path(folder.name)
        self.archive=self.folder/"fixture.zip"
        with zipfile.ZipFile(self.archive,"w") as writer:
            writer.writestr("one",b"payload");writer.writestr("two",b"payload")
    def command(self,*args):
        out=StringIO()
        with patch.object(sys,"argv",["release_guard.py",*map(str,args)]):
            with redirect_stdout(out),redirect_stderr(StringIO()): guard.main()
        return out.getvalue()

    def test_single_archive(self):
        self.assertEqual(self.command(self.archive),"Verified release archives: 1\n")
        self.assertEqual(self.command(self.folder),"Verified release archives: 1\n")

    def test_json_report(self):
        report=json.loads(self.command(self.archive,"--json"))
        self.assertEqual(report["schema"],"rudy.release.archive-report/v1")
        self.assertEqual((report["archive_count"],report["entries"],report["uncompressed_bytes"]),(1,2,14))
        self.assertEqual(report["archives"],[dict(name="fixture.zip",entries=2,uncompressed_bytes=14)])
        self.assertEqual(self.command(self.folder,"--json"),self.command(self.archive,"--json"))
        invalid=self.folder/"later.zip";invalid.write_bytes(b"not an archive")
        out=StringIO()
        with patch.object(sys,"argv",["release_guard.py",str(self.folder),"--json"]):
            with redirect_stdout(out):
                with self.assertRaises((ValueError,zipfile.BadZipFile)): guard.main()
        self.assertEqual(out.getvalue(),"")

    def test_archive_byte_limit(self):
        original=guard.MAX_ARCHIVE
        self.command(self.archive,"--max-archive-bytes",self.archive.stat().st_size)
        with self.assertRaises(ValueError): self.command(self.archive,"--max-archive-bytes",1)
        for value in (0,-1,original+1):
            with self.assertRaises(SystemExit): self.command(self.archive,"--max-archive-bytes",value)
        self.assertEqual(guard.MAX_ARCHIVE,original)

    def test_total_byte_limit(self):
        original=guard.MAX_TOTAL
        self.command(self.archive,"--max-total-bytes",14)
        with self.assertRaises(ValueError): self.command(self.archive,"--max-total-bytes",13)
        for value in (0,-1,original+1):
            with self.assertRaises(SystemExit): self.command(self.archive,"--max-total-bytes",value)
        self.assertEqual(guard.MAX_TOTAL,original)
