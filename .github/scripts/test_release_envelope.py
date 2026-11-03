import gzip
import io
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest

from release_guard import verify


class TarEnvelopeTests(unittest.TestCase):
    def test_valid_and_truncated_codec_footers(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            entry = tarfile.TarInfo("demo.txt")
            entry.size = 3
            archive.addfile(entry, io.BytesIO(b"123"))

        # Compress separate streams so TAR iteration can stop before a damaged
        # trailing stream is decoded, even when the package is very small.
        with tempfile.TemporaryDirectory() as directory:
            for suffix, codec in ((".tar.gz", gzip), (".tar.xz", lzma)):
                with self.subTest(suffix=suffix):
                    path = Path(directory) / ("demo" + suffix)
                    prefix = codec.compress(buffer.getvalue())
                    padding = codec.compress(b"\0" * 65536)
                    path.write_bytes(prefix + padding)
                    self.assertEqual(verify(path), (1, 3))
                    path.write_bytes(prefix + padding[:-4])
                    with self.assertRaises((EOFError, OSError, lzma.LZMAError)):
                        verify(path)
