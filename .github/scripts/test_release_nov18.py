from io import BytesIO
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from release_guard import verify


class StreamOnly(BytesIO):
    def seek(self, *args):
        raise OSError("stream-only")


def zip_bytes(names=("item",), compression=zipfile.ZIP_STORED, streamed=False):
    stream = StreamOnly() if streamed else BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as package:
        for name in names:
            package.writestr(name, b"sample")
    return bytearray(stream.getvalue())


def put_gap_before_directory(data):
    end = len(data) - 22
    directory, = struct.unpack_from("<I", data, end + 16)
    gap = b"\0" * 4
    struct.pack_into("<I", data, end + 16, directory + len(gap))
    data[directory:directory] = gap


class ZipFramingTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "demo.zip"

    def verify(self, data):
        self.path.write_bytes(data)
        return verify(self.path)

    def test_metadata_precedes_payload_io(self):
        data = zip_bytes(("first", "second"))
        self.assertEqual(self.verify(data), (2, 12))
        central = data.rindex(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 34, 1)
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("payload opened early")):
            with self.assertRaisesRegex(ValueError, "another disk"):
                self.verify(data)

    def test_local_filename_checked_before_open(self):
        data = zip_bytes(("caf\u00e9",))
        self.assertEqual(self.verify(data), (1, 6))
        data[30] = ord("d")
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("payload opened early")):
            with self.assertRaisesRegex(ValueError, "ZIP local filename"):
                self.verify(data)

    def test_only_portable_zip_flags(self):
        for compression, flag, valid in (
            (zipfile.ZIP_STORED, 0x0002, False),
            (zipfile.ZIP_DEFLATED, 0x0006, True),
            (zipfile.ZIP_STORED, 0x0800, True),
            (zipfile.ZIP_DEFLATED, 0x1000, False),
        ):
            data = zip_bytes(compression=compression)
            struct.pack_into("<H", data, 6, flag)
            struct.pack_into("<H", data, data.index(b"PK\x01\x02") + 8, flag)
            if valid:
                self.assertEqual(self.verify(data), (1, 6))
            else:
                with self.assertRaisesRegex(ValueError, "ZIP general-purpose flags"):
                    self.verify(data)

    def test_nonstreamed_local_record_extent(self):
        data = zip_bytes()
        self.assertEqual(self.verify(data), (1, 6))
        put_gap_before_directory(data)
        with self.assertRaisesRegex(ValueError, "ZIP local payload extent"):
            self.verify(data)

    def test_streamed_local_record_extent(self):
        data = zip_bytes(streamed=True)
        self.assertEqual(self.verify(data), (1, 6))
        put_gap_before_directory(data)
        with self.assertRaisesRegex(ValueError, "ZIP data descriptor"):
            self.verify(data)
