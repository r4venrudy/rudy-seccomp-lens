"""Validate outer release packages without extracting files or following links."""
from pathlib import Path
import argparse,tarfile,zipfile
MAX_ARCHIVE=512*1024*1024
MAX_MEMBER=512*1024*1024
MAX_TOTAL=2*1024*1024*1024
MAX_ENTRIES=100_000

def verify(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_ARCHIVE:raise ValueError('archive input is not a bounded regular file')
    total=0;count=0
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
            for member in archive.infolist():
                if member.flag_bits&1:raise ValueError('encrypted release member')
                with archive.open(member) as stream:consume(stream,member.file_size)
    elif path.name.endswith(('.tar.gz','.tgz','.tar.xz')):
        with tarfile.open(path) as archive:
            for member in archive:
                if member.isfile():
                    with archive.extractfile(member) as stream:consume(stream,member.size)
                else:consume(None,0)
    else:raise ValueError('unsupported release archive')
    return count,total

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    files=sorted(p for p in args.directory.iterdir() if p.name.endswith(('.zip','.jar','.nupkg','.whl','.tar.gz','.tgz','.tar.xz')))
    if not files:raise ValueError('no release archives were found')
    for file in files:verify(file)
    print('Verified release archives:',len(files))
if __name__=='__main__':main()
