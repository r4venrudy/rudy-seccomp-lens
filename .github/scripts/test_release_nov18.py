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
