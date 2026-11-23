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

    def test_empty_crc(self):
        for name in ("empty","directory/"):
            for compression in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
                output=BytesIO()
                with zipfile.ZipFile(output,"w",compression=compression) as archive:
                    archive.writestr(name,b"");archive.writestr("payload",b"payload")
                data=bytearray(output.getvalue())
                self.assertEqual(self.verify(data),(2,7))
                struct.pack_into("<I",data,14,123)
                central=data.index(b"PK\x01\x02")
                struct.pack_into("<I",data,central+16,123)
                with patch.object(zipfile.ZipFile,"open",side_effect=AssertionError("payload opened before empty CRC preflight")):
                    with self.assertRaisesRegex(ValueError,"empty ZIP member CRC"):
                        self.verify(data)

    def test_ntfs_attributes(self):
        for attributes in (0x10,0x08):
            output=BytesIO()
            with zipfile.ZipFile(output,"w") as archive:
                info=zipfile.ZipInfo("payload");info.create_system=10;info.external_attr=attributes
                archive.writestr(info,b"payload")
            with self.assertRaisesRegex(ValueError,"ZIP directory|ZIP volume"):
                self.verify(output.getvalue())
        output=BytesIO()
        with zipfile.ZipFile(output,"w") as archive:
            info=zipfile.ZipInfo("directory/");info.create_system=10;info.external_attr=0x10
            archive.writestr(info,b"");archive.writestr("directory/payload",b"payload")
        self.assertEqual(self.verify(output.getvalue()),(2,7))
