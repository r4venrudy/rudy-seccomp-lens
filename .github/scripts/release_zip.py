"""Read ZIP framing before handing the archive to the standard decoder."""
import struct
import zipfile
import zlib

MAX_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 100_000


def open_zip(stream):
    stream.seek(0, 2)
    size = stream.tell()
    # Use the same classic/ZIP64 interpretation as ZipFile.
    footer = zipfile._EndRecData(stream)
    if footer is None:
        raise zipfile.BadZipFile("missing ZIP end record")
    # Validate the physical classic footer independently. CPython versions
    # differ in whether _ECD_LOCATION points to the classic or ZIP64 record.
    footer_size = zipfile.sizeEndCentDir
    tail_offset = max(0, size - footer_size - 65535)
    stream.seek(tail_offset)
    tail = stream.read(size - tail_offset)
    classic = len(tail) - footer_size
    signature = b"PK\x05\x06"
    if not tail.startswith(signature, classic) or tail[-2:] != b"\0\0":
        classic = tail.rfind(signature)
    if classic < 0 or classic + footer_size + footer[zipfile._ECD_COMMENT_SIZE] != len(tail):
        raise ValueError("ZIP footer extent disagrees with file size")
    classic_offset = tail_offset + classic
    count = footer[zipfile._ECD_ENTRIES_TOTAL]
    if footer[zipfile._ECD_DISK_NUMBER] or footer[zipfile._ECD_DISK_START] or footer[zipfile._ECD_ENTRIES_THIS_DISK] != count:
        raise ValueError("ZIP disk or entry count is inconsistent")
    if footer[zipfile._ECD_SIZE] > MAX_DIRECTORY_BYTES or count > MAX_DIRECTORY_ENTRIES:
        raise ValueError("ZIP directory exceeds resource limits")
    directory_size = footer[zipfile._ECD_SIZE]
    directory_end = footer[zipfile._ECD_LOCATION]
    if footer[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64 and directory_end == classic_offset:
        directory_end -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
    start = directory_end - directory_size
    if start < 0:
        raise zipfile.BadZipFile("invalid ZIP directory start")
    stream.seek(start)
    remaining = directory_size
    actual = 0
    while remaining:
        if remaining < 46:
            raise zipfile.BadZipFile("truncated ZIP directory header")
        header = stream.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise zipfile.BadZipFile("invalid ZIP directory header")
        variable_size = sum(struct.unpack_from("<HHH", header, 28))
        if 46 + variable_size > remaining:
            raise zipfile.BadZipFile("ZIP directory entry extends beyond directory")
        actual += 1
        if actual > count:
            raise ValueError("ZIP directory entry count disagrees with footer")
        stream.seek(variable_size, 1)
        remaining -= 46 + variable_size
    if actual != count:
        raise ValueError("ZIP directory entry count disagrees with footer")
    return zipfile.ZipFile(stream)


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


def validate_deflate(archive, member):
    """Confirm that the raw DEFLATE stream occupies the entire packed region."""
    stream = archive.fp
    stream.seek(member.header_offset + 26)
    local_sizes = stream.read(4)
    if len(local_sizes) != 4:
        raise ValueError("truncated ZIP local lengths")
    stream.seek(sum(struct.unpack("<HH", local_sizes)), 1)

    decoder = zlib.decompressobj(-15)
    remaining = member.compress_size
    decoded = 0
    block_size = 65536
    try:
        while remaining:
            chunk = stream.read(min(remaining, block_size))
            if not chunk:
                raise ValueError("truncated ZIP DEFLATE stream")
            remaining -= len(chunk)
            while True:
                output = decoder.decompress(chunk, block_size)
                decoded += len(output)
                if decoded > member.file_size:
                    raise ValueError("ZIP DEFLATE stream exceeds declared size")
                if decoder.eof:
                    if decoder.unused_data or remaining or decoded != member.file_size:
                        raise ValueError("ZIP DEFLATE stream disagrees with member boundary or size")
                    return
                chunk = decoder.unconsumed_tail
                if not chunk and len(output) < block_size:
                    break
    except zlib.error as error:
        raise ValueError("invalid ZIP DEFLATE stream") from error
    raise ValueError("ZIP DEFLATE stream is missing its final block")
