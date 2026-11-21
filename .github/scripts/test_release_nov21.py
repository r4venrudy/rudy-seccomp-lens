from contextlib import redirect_stdout
from io import BytesIO, StringIO
import gzip
import lzma
from pathlib import Path
import struct
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

import release_guard as guard

def basic_zip(system=3, attributes=0):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        member = zipfile.ZipInfo("payload.txt")
        member.create_system = system
        member.external_attr = attributes
        archive.writestr(member, b"payload")
    return stream.getvalue()

def zip64():
    base = basic_zip()
    end = len(base) - 22
    size, offset = struct.unpack_from("<II", base, end + 12)
    extended = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, size, offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end, 1)
    return bytearray(base[:end] + extended + locator + base[end:])

def tar_record(name, payload=b"payload", kind=tarfile.REGTYPE):
    member = tarfile.TarInfo(name)
    member.type, member.size = kind, len(payload)
    return member.tobuf(format=tarfile.USTAR_FORMAT) + payload + bytes((-len(payload)) % 512)

def pax(value=b"comment=fixture\n"):
    size = len(value) + 2
    while size != len(str(size)) + 1 + len(value):
        size = len(str(size)) + 1 + len(value)
    return str(size).encode("ascii") + b" " + value

class ReleaseFramingRegressions(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def verify(self, data, name="fixture.zip"):
        path = self.folder / name
        path.write_bytes(data)
        return guard.verify(path)

    def test_case_insensitive_archive_dispatch(self):
        (self.folder / "good.zip").write_bytes(basic_zip())
        with zipfile.ZipFile(self.folder / "bad.ZIP", "w") as archive:
            archive.writestr("../escape", b"payload")
        with patch.object(sys, "argv", ["release_guard.py", str(self.folder)]):
            with redirect_stdout(StringIO()):
                with self.assertRaisesRegex(ValueError, "parent traversal"):
                    guard.main()
        for suffix in ("ZIP", "JAR", "NUPKG", "WHL", "ZiP"):
            self.assertEqual(self.verify(basic_zip(), "safe."+suffix), (1, 7))
        raw = tar_record("payload") + bytes(1024)
        for suffix in ("TAR.GZ", "TGZ", "TaR.Gz"):
            self.assertEqual(self.verify(gzip.compress(raw), "safe."+suffix), (1, 7))
        self.assertEqual(self.verify(lzma.compress(raw), "safe.TAR.XZ"), (1, 7))

    def test_zip64_locator(self):
        data = zip64()
        self.assertEqual(self.verify(data), (1, 7))
        # Preserve the same concatenated-prefix support as the standard reader.
        self.assertEqual(self.verify(b"prefix" + data), (1, 7))
        locator = len(data) - 22 - 20
        for offset, format, value in ((8, "<Q", 0), (8, "<Q", len(data)), (16, "<I", 0)):
            changed = bytearray(data)
            struct.pack_into(format, changed, locator + offset, value)
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                self.verify(changed)

    def test_classic_zip64_agreement(self):
        data = zip64()
        end = len(data) - 22
        for offset, format, value in ((4,"<H",1), (6,"<H",1), (8,"<H",2), (10,"<H",2), (12,"<I",1), (16,"<I",0)):
            changed = bytearray(data)
            struct.pack_into(format, changed, end + offset, value)
            with self.assertRaisesRegex(ValueError, "classic and ZIP64"):
                self.verify(changed)
        for offset, format, sentinel in ((4,"<H",0xffff), (6,"<H",0xffff), (8,"<H",0xffff), (10,"<H",0xffff), (12,"<I",0xffffffff), (16,"<I",0xffffffff)):
            struct.pack_into(format, data, end + offset, sentinel)
        self.assertEqual(self.verify(data), (1, 7))

    def test_zip64_end_record_profile(self):
        data = zip64()
        end64 = len(data) - 22 - 20 - 56
        for offset, format, value in ((4,"<Q",0), (4,"<Q",43), (4,"<Q",45), (4,"<Q",0xffffffffffffffff), (14,"<H",0), (14,"<H",44)):
            changed = bytearray(data)
            struct.pack_into(format, changed, end64 + offset, value)
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                self.verify(changed)

    def test_tar_extension_padding(self):
        for kind, payload in ((tarfile.GNUTYPE_LONGNAME, b"payload\0"), (tarfile.XHDTYPE, pax()), (tarfile.XGLTYPE, pax()), (tarfile.SOLARIS_XHDTYPE, pax())):
            clean = tar_record("extension", payload, kind) + tar_record("payload") + bytes(1024)
            dirty = bytearray(clean)
            dirty[512 + len(payload)] = 1
            for suffix, compressor in (("tar.gz", gzip.compress), ("tar.xz", lzma.compress)):
                self.assertEqual(self.verify(compressor(clean), "clean."+suffix), (1, 7))
                with self.assertRaisesRegex(ValueError, "TAR extension padding"):
                    self.verify(compressor(dirty), "dirty."+suffix)

    def test_vfat_directory_marker(self):
        self.assertEqual(self.verify(basic_zip(14, 0x20)), (1, 7))
        self.assertEqual(self.verify(basic_zip(3, 0x10)), (1, 7))
        with self.assertRaisesRegex(ValueError, "ZIP directory lacks"):
            self.verify(basic_zip(14, 0x10))
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            directory = zipfile.ZipInfo("directory/")
            directory.create_system, directory.external_attr = 14, 0x10
            archive.writestr(directory, b"")
            archive.writestr("directory/payload", b"payload")
        self.assertEqual(self.verify(stream.getvalue()), (2, 7))
