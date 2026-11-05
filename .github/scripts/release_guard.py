"""Validate outer release packages without extracting files or following links."""
import gzip
import lzma
from pathlib import Path
import argparse,tarfile,zipfile,stat
MAX_ARCHIVE=512*1024*1024
MAX_MEMBER=512*1024*1024
MAX_TOTAL=2*1024*1024*1024
MAX_ENTRIES=100_000

def validate_paths(records):
    import posixpath,stat,unicodedata
    from pathlib import PurePosixPath
    paths={}
    spellings={}
    for name,directory,linked,special in records:
        if linked or special:raise ValueError('link or special file in portable release')
        if name in ('.','./') and directory:continue
        if not name or name.startswith('/') or '\\' in name or ':' in name or any(ord(c)<32 or ord(c)==127 for c in name):raise ValueError('unsafe release member name')
        if '..' in PurePosixPath(name).parts:raise ValueError('parent traversal in release')
        normalized=posixpath.normpath(name).rstrip('/')
        if normalized in ('','.','..'):raise ValueError('empty release member')
        parts=normalized.split('/')
        if any(character in '<>"|?*' for character in name):
            raise ValueError('nonportable Windows member name')
        devices={'con','prn','aux','nul'}|{'com'+str(i) for i in range(1,10)}|{'lpt'+str(i) for i in range(1,10)}
        devices |= {prefix+digit for prefix in ('com','lpt') for digit in '\u00b9\u00b2\u00b3'}
        if any(p.endswith(('.', ' ')) or p.split('.')[0].casefold() in devices for p in parts):raise ValueError('nonportable Windows member name')
        key=unicodedata.normalize('NFC',normalized).casefold()
        if key in paths:raise ValueError('duplicate or case/normalization-colliding release member')
        paths[key]=directory
        for i in range(1,len(parts)+1):
            spelling='/'.join(parts[:i])
            canonical=unicodedata.normalize('NFC',spelling).casefold()
            previous=spellings.setdefault(canonical,spelling)
            if previous!=spelling:raise ValueError('colliding release path prefix spellings')
    for key in paths:
        parts=key.split('/')
        for i in range(1,len(parts)):
            parent='/'.join(parts[:i])
            if parent in paths and not paths[parent]:raise ValueError('file used as a release directory')


def verify_compression_envelope(path):
    # TAR iteration can finish at its end marker without reading the codec footer.
    # Limit all decoded bytes, including headers, padding and trailing data.
    limit = MAX_TOTAL + 128 * 1024 * 1024
    opener = lzma.open if path.name.endswith(".tar.xz") else gzip.open
    decoded = 0
    with opener(path, "rb") as stream:
        while chunk := stream.read(65536):
            decoded += len(chunk)
            if decoded > limit:
                raise ValueError("compressed TAR envelope exceeds resource limits")



def validate_zip_metadata(archive, member):
    # ZipFile uses central metadata to decompress. Verify the corresponding
    # local record advertises the same flags and compression method.
    position = archive.fp.tell()
    try:
        archive.fp.seek(member.header_offset)
        header = archive.fp.read(10)
        if len(header) != 10 or header[:4] != b"PK\x03\x04":
            raise ValueError("invalid ZIP local metadata")
        import struct
        _, flags, method = struct.unpack("<HHH", header[4:])
        if flags != member.flag_bits or method != member.compress_type:
            raise ValueError("ZIP local metadata disagrees with central record")
    finally:
        archive.fp.seek(position)

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
    if path.name.endswith(('.zip','.jar','.nupkg','.whl')):
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist())>MAX_ENTRIES:raise ValueError('too many archive records')
            validate_paths([(m.orig_filename,m.is_dir(),stat.S_ISLNK(m.external_attr>>16),(m.external_attr>>16)&0o170000 not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK)) for m in archive.infolist()])
            for member in archive.infolist():
                validate_zip_metadata(archive, member)
                if member.flag_bits&1:raise ValueError('encrypted release member')
                kind=stat.S_IFMT(member.external_attr>>16) if member.create_system==3 else 0
                if member.is_dir() and (member.file_size or kind==stat.S_IFREG):
                    raise ValueError('invalid ZIP directory payload or type')
                if not member.is_dir() and kind==stat.S_IFDIR:
                    raise ValueError('ZIP directory lacks a trailing slash')
                has_file_payload |= not member.is_dir() and member.file_size>0
                with archive.open(member) as stream:consume(stream,member.file_size)
    elif path.name.endswith(('.tar.gz','.tgz','.tar.xz')):
        verify_compression_envelope(path)
        with tarfile.open(path) as archive:
            records=[]
            for member in archive:
                if member.sparse is not None:
                    raise ValueError('sparse TAR members are outside the release profile')
                if member.isdir() and member.size:
                    raise ValueError('TAR directory declares a payload')
                records.append((member.name,member.isdir(),member.issym() or member.islnk(),not(member.isfile() or member.isdir() or member.issym() or member.islnk())))
                if member.isfile():
                    has_file_payload |= member.size>0
                    with archive.extractfile(member) as stream:consume(stream,member.size)
                else:consume(None,0)
            validate_paths(records)
            archive.fileobj.seek(archive.offset)
            if archive.fileobj.read(1024)!=bytes(1024):
                raise ValueError('TAR end requires two zero records')
            padding=0
            while tail:=archive.fileobj.read(65536):
                if tail.strip(b'\0'):
                    raise ValueError('nonzero bytes after TAR end records')
                padding+=len(tail)
            if padding%512:
                raise ValueError('partial record after TAR end')
    else:raise ValueError('unsupported release archive')
    if not has_file_payload:
        raise ValueError('release archive contains no nonempty file')
    return count,total

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    files=sorted(p for p in args.directory.iterdir() if p.name.endswith(('.zip','.jar','.nupkg','.whl','.tar.gz','.tgz','.tar.xz')))
    if not files:raise ValueError('no release archives were found')
    for file in files:verify(file)
    print('Verified release archives:',len(files))
if __name__=='__main__':main()
