"""Validate outer release packages without extracting files or following links."""
import gzip
import struct
import lzma
from pathlib import Path
from release_zip import open_zip, validate_deflate, validate_descriptor
import argparse,tarfile,zipfile,stat
MAX_ARCHIVE=512*1024*1024
MAX_MEMBER=512*1024*1024
MAX_TOTAL=2*1024*1024*1024
MAX_ENTRIES=100_000

def validate_paths(records):
    import posixpath,stat,unicodedata
    from pathlib import PurePosixPath
    def portable_key(value):
        # Canonical caseless matching needs normalization after folding too.
        return unicodedata.normalize('NFC', unicodedata.normalize('NFD', value).casefold())
    paths={}
    spellings={}
    for name,directory,linked,special in records:
        if linked or special:raise ValueError('link or special file in portable release')
        if name in ('.','./') and directory:continue
        if not name or name.startswith('/') or '\\' in name or ':' in name or any(unicodedata.category(c)=='Cc' for c in name):raise ValueError('unsafe release member name')
        if '..' in PurePosixPath(name).parts:raise ValueError('parent traversal in release')
        if any(unicodedata.category(c)=='Cs' for c in name):
            raise ValueError('invalid Unicode in release member name')
        normalized=posixpath.normpath(name).rstrip('/')
        if normalized in ('','.','..'):raise ValueError('empty release member')
        parts=normalized.split('/')
        if len(name.encode('utf-8')) > 4096 or len(parts) > 128:
            raise ValueError('release member exceeds path budget')
        if any(len(part.encode('utf-8')) > 255 for part in parts):
            raise ValueError('release path component exceeds 255 UTF-8 bytes')
        if any(character in '<>"|?*' for character in name):
            raise ValueError('nonportable Windows member name')
        devices={'con','prn','aux','nul','conin$','conout$'}|{'com'+str(i) for i in range(1,10)}|{'lpt'+str(i) for i in range(1,10)}
        devices |= {prefix+digit for prefix in ('com','lpt') for digit in '\u00b9\u00b2\u00b3'}
        if any(p.endswith(('.', ' ')) or p.split('.')[0].casefold() in devices for p in parts):raise ValueError('nonportable Windows member name')
        key=portable_key(normalized)
        if key in paths:raise ValueError('duplicate or case/normalization-colliding release member')
        paths[key]=directory
        for i in range(1,len(parts)+1):
            spelling='/'.join(parts[:i])
            canonical=portable_key(spelling)
            previous=spellings.setdefault(canonical,spelling)
            if previous!=spelling:raise ValueError('colliding release path prefix spellings')
    for key in paths:
        parts=key.split('/')
        for i in range(1,len(parts)):
            parent='/'.join(parts[:i])
            if parent in paths and not paths[parent]:raise ValueError('file used as a release directory')


def verify_xz_envelope(path, limit):
    decoded = 0
    streams = 0
    with path.open("rb") as stream:
        pending = stream.read(65536)
        while pending:
            if len(pending) < 6:
                pending += stream.read(6 - len(pending))
            if not pending.startswith(bytes.fromhex("fd377a585a00")):
                raise ValueError("invalid XZ stream header")
            streams += 1
            if streams > 4096:
                raise ValueError("XZ stream count exceeds resource limit")
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024 * 1024)
            while not decoder.eof:
                if decoder.needs_input and not pending:
                    pending = stream.read(65536)
                    if not pending:
                        raise EOFError("truncated XZ compression envelope")
                try:
                    decoded += len(decoder.decompress(pending, max_length=65536))
                except lzma.LZMAError as error:
                    raise ValueError("invalid XZ compression envelope") from error
                pending = b""
                if decoded > limit:
                    raise ValueError("compressed TAR envelope exceeds resource limits")
            pending = decoder.unused_data or stream.read(65536)
            padding = 0
            while pending:
                remainder = pending.lstrip(bytes(1))
                padding += len(pending) - len(remainder)
                pending = remainder or stream.read(65536)
                if remainder:
                    break
            if padding % 4:
                raise ValueError("invalid XZ stream padding")
            # The TAR reader uses LZMAFile, which can stop at inter-stream padding.
            if padding and pending:
                raise ValueError("XZ stream padding is allowed only after the final stream")
    if streams == 0:
        raise ValueError("empty XZ compression envelope")
    return decoded


MAX_GZIP_STREAMS = 4096


def verify_gzip_envelope(path, limit):
    # zlib's gzip decoder checks FHCRC as well as the payload CRC and ISIZE.
    import zlib
    decoded = 0
    streams = 0
    with path.open("rb") as stream:
        pending = stream.read(65536)
        while pending:
            if streams:
                pending = pending.lstrip(bytes(1))
                if not pending:
                    pending = stream.read(65536)
                    continue
            streams += 1
            if streams > MAX_GZIP_STREAMS:
                raise ValueError("gzip stream count exceeds resource limit")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            while not decoder.eof:
                if not pending:
                    pending = stream.read(65536)
                    if not pending:
                        raise EOFError("truncated gzip compression envelope")
                try:
                    decoded += len(decoder.decompress(pending, 65536))
                except zlib.error as error:
                    raise ValueError("invalid gzip compression envelope") from error
                pending = decoder.unconsumed_tail
                if decoded > limit:
                    raise ValueError("compressed TAR envelope exceeds resource limits")
            pending = decoder.unused_data or stream.read(65536)
    if not streams:
        raise ValueError("empty gzip compression envelope")
    return decoded


def verify_compression_envelope(path):
    # TAR iteration can finish at its end marker without reading the codec footer.
    # Limit all decoded bytes, including headers, padding and trailing data.
    limit = MAX_TOTAL + 128 * 1024 * 1024
    if path.name.lower().endswith(".tar.xz"):
        return verify_xz_envelope(path, limit)
    return verify_gzip_envelope(path, limit)


def validate_zip_extra(data, record, filename=None, flags=0):
    cursor = 0
    structural = set()
    while cursor < len(data):
        if len(data) - cursor < 4:
            raise ValueError(f"truncated {record} ZIP extra field header")
        kind, length = struct.unpack_from("<HH", data, cursor)
        cursor += 4 + length
        if cursor > len(data):
            raise ValueError(f"truncated {record} ZIP extra field payload")
        if kind == 0x7075 and filename is not None:
            import zlib
            payload = data[cursor - length:cursor]
            raw = filename.encode("utf-8" if flags & (1 << 11) else "cp437")
            if len(payload) < 5 or payload[0] != 1:
                raise ValueError(f"invalid {record} ZIP Unicode path header")
            if struct.unpack_from("<I", payload, 1)[0] != zlib.crc32(raw):
                raise ValueError(f"invalid {record} ZIP Unicode path checksum")
            try:
                alias = payload[5:].decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"invalid {record} ZIP Unicode path encoding") from error
            if alias != filename:
                raise ValueError(f"{record} ZIP Unicode path changes the audited filename")
        # A record has only one ZIP64 structure and one Unicode path override.
        if kind in (0x0001, 0x7075):
            if kind in structural:
                raise ValueError(f"duplicate {record} ZIP extra field: 0x{kind:04x}")
            structural.add(kind)


def validate_zip_metadata(archive, member):
    # ZipFile uses central metadata to decompress. Verify the corresponding
    # local record advertises the same flags and compression method.
    position = archive.fp.tell()
    try:
        archive.fp.seek(member.header_offset)
        header = archive.fp.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise ValueError("invalid ZIP local metadata")
        version, _, flags, method = struct.unpack_from("<BBHH", header, 4)
        if flags != member.flag_bits or method != member.compress_type:
            raise ValueError("ZIP local metadata disagrees with central record")
        minimum = 20 if method == zipfile.ZIP_DEFLATED else 10
        if min(version, member.extract_version) < minimum:
            raise ValueError("ZIP extraction version is below the member's feature minimum")
        name_size, extra_size = struct.unpack_from("<HH", header, 26)
        payload_end = member.header_offset + 30 + name_size + extra_size + member.compress_size
        if not flags & 8 and payload_end != member._end_offset:
            raise ValueError("ZIP local payload extent disagrees with record boundary")
        encoding = "utf-8" if flags & (1 << 11) else "cp437"
        if archive.fp.read(name_size) != member.orig_filename.encode(encoding):
            raise ValueError("ZIP local filename disagrees with central record")
        local_extra = archive.fp.read(extra_size)
        if len(local_extra) != extra_size:
            raise ValueError("truncated local ZIP extra field region")
        validate_zip_extra(local_extra, "local", member.orig_filename, flags)
        zip64 = False
        for extra in (local_extra, member.extra):
            cursor = 0
            while cursor < len(extra):
                kind, length = struct.unpack_from("<HH", extra, cursor)
                zip64 |= kind == 1 and length > 0
                cursor += 4 + length
        if zip64 and min(version, member.extract_version) < 45:
            raise ValueError("ZIP64 extraction version is below 4.5")
        if flags & 8:
            crc, packed, size = struct.unpack_from("<III", header, 14)
            if (crc not in (0, member.CRC)
                    or packed not in (0, 0xFFFFFFFF, member.compress_size)
                    or size not in (0, 0xFFFFFFFF, member.file_size)):
                raise ValueError("streamed ZIP local fields disagree with central record")
            return
        crc, packed, size = struct.unpack_from("<III", header, 14)
        if size == 0xFFFFFFFF or packed == 0xFFFFFFFF:
            extra = local_extra
            cursor = 0
            while cursor + 4 <= len(extra):
                kind, length = struct.unpack_from("<HH", extra, cursor)
                cursor += 4
                if cursor + length > len(extra):
                    break
                if kind == 1:
                    payload = extra[cursor:cursor + length]
                    required = 8 * ((size == 0xFFFFFFFF) + (packed == 0xFFFFFFFF))
                    if len(payload) < required:
                        break
                    used = 0
                    if size == 0xFFFFFFFF and len(payload) >= 8:
                        size = struct.unpack_from("<Q", payload)[0]
                        used = 8
                    if packed == 0xFFFFFFFF and len(payload) >= used + 8:
                        packed = struct.unpack_from("<Q", payload, used)[0]
                    break
                cursor += length
        if (crc, packed, size) != (member.CRC, member.compress_size, member.file_size):
            raise ValueError("ZIP local CRC or size disagrees with central record")
    finally:
        archive.fp.seek(position)

MAX_TAR_EXTENSION_BYTES = 1024 * 1024
MAX_TAR_EXTENSION_TOTAL = 16 * 1024 * 1024
MAX_TAR_EXTENSION_DEPTH = 32
TAR_EXTENSION_TYPES = (
    tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
    tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
)


class ReleaseTarInfo(tarfile.TarInfo):
    """Reject unsupported sparse records before the standard reader expands them."""

    def _proc_member(self, archive):
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError("sparse TAR members are outside the release profile")
        if self.type in TAR_EXTENSION_TYPES:
            if self.size < 0 or self.size > MAX_TAR_EXTENSION_BYTES:
                raise ValueError("TAR extension exceeds the metadata limit")
            padded = (self.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE
            padding = (-self.size) % tarfile.BLOCKSIZE
            if padding:
                position = archive.fileobj.tell()
                try:
                    archive.fileobj.seek(position + self.size)
                    if archive.fileobj.read(padding) != bytes(padding):
                        raise ValueError("truncated or nonzero TAR extension padding")
                finally:
                    archive.fileobj.seek(position)
            total = getattr(archive, "_release_extension_bytes", 0) + tarfile.BLOCKSIZE + padded
            if total > MAX_TAR_EXTENSION_TOTAL:
                raise ValueError("TAR extension metadata exceeds the aggregate limit")
            archive._release_extension_bytes = total
            depth = getattr(archive, "_release_extension_depth", 0)
            if depth >= MAX_TAR_EXTENSION_DEPTH:
                raise ValueError("TAR extension nesting exceeds the recursion limit")
            archive._release_extension_depth = depth + 1
            try:
                return super()._proc_member(archive)
            finally:
                archive._release_extension_depth = depth
        return super()._proc_member(archive)

    def _proc_gnusparse_00(self, member, raw_headers):
        raise ValueError("sparse TAR members are outside the release profile")

    def _proc_gnusparse_01(self, member, pax_headers):
        raise ValueError("sparse TAR members are outside the release profile")

    def _proc_gnusparse_10(self, member, pax_headers, archive):
        raise ValueError("sparse TAR members are outside the release profile")


def verify(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_ARCHIVE:raise ValueError('archive input is not a bounded regular file')
    total=0;count=0
    has_file_payload=False
    def consume(stream,size):
        nonlocal total,count
        count+=1;total+=size
        if count>MAX_ENTRIES or size<0 or size>MAX_MEMBER or total>MAX_TOTAL:raise ValueError('release archive exceeds resource limits')
        actual=0
        if stream:
            while True:
                chunk=stream.read(65536)
                if not chunk:break
                actual+=len(chunk)
                if actual>size:raise ValueError('member exceeds declared size')
        if actual!=size:raise ValueError('member is truncated')
    if path.name.lower().endswith(('.zip','.jar','.nupkg','.whl')):
        with path.open("rb") as package, open_zip(package) as archive:
            if len(archive.infolist())>MAX_ENTRIES:raise ValueError('too many archive records')
            validate_paths([(m.orig_filename,m.is_dir(),stat.S_ISLNK(m.external_attr>>16),(m.external_attr>>16)&0o170000 not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK)) for m in archive.infolist()])
            members = archive.infolist()
            if len({member.header_offset for member in members}) != len(members):
                raise ValueError('duplicate ZIP local header offset')
            if (any(member.file_size < 0 or member.file_size > MAX_MEMBER for member in members)
                    or sum(member.file_size for member in members) > MAX_TOTAL):
                raise ValueError('release archive exceeds resource limits')
            for member in members:
                name = member.orig_filename
                path_text = name[:-1] if member.is_dir() else name
                if not name.startswith('/') and any(part in ('', '.') for part in path_text.split('/')):
                    raise ValueError('noncanonical ZIP member path')
                validate_zip_extra(member.extra, "central", member.orig_filename, member.flag_bits)
                if member.volume != 0:
                    raise ValueError('ZIP member references another disk')
                validate_zip_metadata(archive, member)
                validate_descriptor(archive, member)
                if member.compress_type == zipfile.ZIP_STORED and member.compress_size != member.file_size:
                    raise ValueError('stored ZIP member size differs from compressed size')
                if member.flag_bits & 0x2041:  # traditional, strong, or masked header
                    raise ValueError('encrypted release member')
                if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError('unsupported release ZIP compression')
                supported_flags = (1 << 3) | (1 << 11)  # descriptor and UTF-8 name
                if member.compress_type == zipfile.ZIP_DEFLATED:
                    supported_flags |= (1 << 1) | (1 << 2)
                if member.flag_bits & ~supported_flags:
                    raise ValueError('unsupported ZIP general-purpose flags')
                unix_mode = member.external_attr >> 16 if member.create_system in (3, 19) else 0
                kind = stat.S_IFMT(unix_mode)
                if member.create_system in (0, 14) and member.external_attr & 0x08:
                    raise ValueError('ZIP volume label is outside the release profile')
                if unix_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise ValueError('privileged ZIP mode in portable release')
                if member.is_dir() and (member.file_size or kind==stat.S_IFREG):
                    raise ValueError('invalid ZIP directory payload or type')
                dos_directory = member.create_system in (0, 14) and bool(member.external_attr & 0x10)
                if not member.is_dir() and (kind == stat.S_IFDIR or dos_directory):
                    raise ValueError('ZIP directory lacks a trailing slash')
            for member in members:
                has_file_payload |= not member.is_dir() and member.file_size>0
                with archive.open(member) as stream:consume(stream,member.file_size)
                if member.compress_type == zipfile.ZIP_DEFLATED:
                    validate_deflate(archive, member)
    elif path.name.lower().endswith(('.tar.gz','.tgz','.tar.xz')):
        decoded_size = verify_compression_envelope(path)
        with tarfile.open(path, tarinfo=ReleaseTarInfo) as archive:
            records=[]
            members = []
            declared_total = 0
            for member in archive:
                if member.sparse is not None:
                    raise ValueError('sparse TAR members are outside the release profile')
                if member.isfile() and member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    raise ValueError('unsupported TAR file type')
                if member.mode & (stat.S_ISUID | stat.S_ISGID):
                    raise ValueError('privileged TAR mode in portable release')
                if member.isdir() and member.size:
                    raise ValueError('TAR directory declares a payload')
                records.append((member.name,member.isdir(),member.issym() or member.islnk(),not(member.isfile() or member.isdir() or member.issym() or member.islnk())))
                declared_total += member.size
                if (len(members) >= MAX_ENTRIES or member.size < 0 or member.size > MAX_MEMBER
                        or declared_total > MAX_TOTAL):
                    raise ValueError('release archive exceeds resource limits')
                members.append(member)
            validate_paths(records)
            for member in members:
                if member.isfile():
                    has_file_payload |= member.size>0
                    with archive.extractfile(member) as stream:consume(stream,member.size)
                    padding_size = (-member.size) % tarfile.BLOCKSIZE
                    if padding_size:
                        archive.fileobj.seek(member.offset_data + member.size)
                        if archive.fileobj.read(padding_size) != bytes(padding_size):
                            raise ValueError('truncated or nonzero TAR member padding')
                else:consume(None,0)
            archive.fileobj.seek(archive.offset)
            if archive.fileobj.read(1024)!=bytes(1024):
                raise ValueError('TAR end requires two zero records')
            padding = decoded_size - archive.fileobj.tell()
            if padding < 0:
                raise ValueError('partial record after TAR end')
            remaining = padding
            while remaining:
                tail = archive.fileobj.read(min(65536, remaining))
                if not tail or tail.strip(b'\0'):
                    raise ValueError('nonzero bytes after TAR end records')
                remaining -= len(tail)
            if padding % 512:
                raise ValueError('partial record after TAR end')
    else:raise ValueError('unsupported release archive')
    if not has_file_payload:
        raise ValueError('release archive contains no nonempty file')
    return count,total

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    files=sorted(p for p in args.directory.iterdir() if p.name.lower().endswith(('.zip','.jar','.nupkg','.whl','.tar.gz','.tgz','.tar.xz')))
    if not files:raise ValueError('no release archives were found')
    for file in files:verify(file)
    print('Verified release archives:',len(files))
if __name__=='__main__':main()
