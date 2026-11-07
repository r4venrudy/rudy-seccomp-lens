"""Read ZIP framing before handing the archive to the standard decoder."""
import struct
import zipfile

MAX_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 100_000


def open_zip(stream):
    stream.seek(0, 2)
    size = stream.tell()
    # Use the same classic/ZIP64 interpretation as ZipFile.
    footer = zipfile._EndRecData(stream)
    if footer is None:
        raise zipfile.BadZipFile("missing ZIP end record")
    if footer[zipfile._ECD_LOCATION] + zipfile.sizeEndCentDir + footer[zipfile._ECD_COMMENT_SIZE] != size:
        raise ValueError("ZIP footer extent disagrees with file size")
    count = footer[zipfile._ECD_ENTRIES_TOTAL]
    if footer[zipfile._ECD_DISK_NUMBER] or footer[zipfile._ECD_DISK_START] or footer[zipfile._ECD_ENTRIES_THIS_DISK] != count:
        raise ValueError("ZIP disk or entry count is inconsistent")
    if footer[zipfile._ECD_SIZE] > MAX_DIRECTORY_BYTES or count > MAX_DIRECTORY_ENTRIES:
        raise ValueError("ZIP directory exceeds resource limits")
    archive = zipfile.ZipFile(stream)
    if len(archive.infolist()) != count:
        archive.close()
        raise ValueError("ZIP directory entry count disagrees with footer")
    return archive


def validate_descriptor(archive, member):
    if not member.flag_bits & 8:
        return
    with_header = archive.fp
    with_header.seek(member.header_offset)
    header = with_header.read(30)
    if len(header) != 30:
        raise ValueError("truncated ZIP data descriptor header")
    packed, size, name_size, extra_size = struct.unpack("<IIHH", header[18:])
    start = member.header_offset + 30 + name_size + extra_size + member.compress_size
    # ZipFile derives this boundary from the next local record or the directory.
    remaining = member._end_offset - start
    if remaining < 12:
        raise ValueError("missing or truncated ZIP data descriptor")
    with_header.seek(start)
    trailer = with_header.read(min(remaining, 24))
    widths = ("<IQQ",) if 0xFFFFFFFF in (packed, size) else ("<III", "<IQQ")
    offsets = (0, 4) if trailer.startswith(b"PK\x07\x08") else (0,)
    expected = (member.CRC, member.compress_size, member.file_size)
    matches = sum(
        struct.unpack_from(layout, trailer, offset) == expected
        for layout in widths
        for offset in offsets
        if len(trailer) >= offset + struct.calcsize(layout)
    )
    if matches != 1:
        raise ValueError("ZIP data descriptor disagrees with central record")
