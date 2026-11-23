from io import BytesIO
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile
import zlib
import release_guard as guard

def nameless_zip():
    data=b"payload";crc=zlib.crc32(data)
    local=struct.pack("<4s5H3I2H",b"PK\x03\x04",20,0,0,0,33,crc,len(data),len(data),0,0)+data
    central=struct.pack("<4s6H3I5H2I",b"PK\x01\x02",3*256+20,20,0,0,0,33,crc,len(data),len(data),0,0,0,0,0,0,0)
    return local+central+struct.pack("<4s4H2IH",b"PK\x05\x06",0,0,1,1,len(central),len(local),0)

class ReleaseEmptyRecords(unittest.TestCase):
    def setUp(self):
        folder=TemporaryDirectory();self.addCleanup(folder.cleanup);self.folder=Path(folder.name)
    def verify(self,data):
        path=self.folder/"fixture.zip";path.write_bytes(data);return guard.verify(path)

    def test_empty_filename(self):
        with patch.object(zipfile,"ZipFile",side_effect=AssertionError("metadata allocated before empty filename validation")):
            with self.assertRaisesRegex(ValueError,"empty ZIP member name"):
                self.verify(nameless_zip())
        with self.assertRaisesRegex(ValueError,"empty ZIP member name"):
            self.verify(nameless_zip())
