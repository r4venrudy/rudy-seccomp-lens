from io import BytesIO
import gzip
import lzma
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import release_guard as guard


def record(name, payload=b"payload", kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(payload)
    return info.tobuf(format=tarfile.USTAR_FORMAT) + payload + bytes((-len(payload)) % 512)


def pax(value=b"comment=fixture\n"):
    size = len(value) + 2
    while size != len(str(size)) + 1 + len(value):
        size = len(str(size)) + 1 + len(value)
    return str(size).encode("ascii") + b" " + value


class TarMetadataLimits(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)

    def verify(self, data, xz=False):
        file = self.folder / ("demo.tar.xz" if xz else "demo.tar.gz")
        data += bytes(1024)
        file.write_bytes(lzma.compress(data) if xz else gzip.compress(data))
        return guard.verify(file)

    def test_gnu_sparse_rejected_before_decoder(self):
        data = record("sparse", kind=tarfile.GNUTYPE_SPARSE)
        for xz in (False, True):
            with patch.object(tarfile.TarInfo, "_proc_sparse", side_effect=AssertionError("sparse decoder called")):
                with self.assertRaisesRegex(ValueError, "sparse TAR members"):
                    self.verify(data, xz=xz)
