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
