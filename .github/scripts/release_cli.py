"""Command interface for portable release-archive verification."""
import argparse
import os
from pathlib import Path

SUFFIXES=(".zip",".jar",".nupkg",".whl",".tar.gz",".tgz",".tar.xz")

def candidates(path,limit):
    if path.is_file() or path.is_symlink():
        return [path]
    if not path.is_dir():
        raise ValueError("release input must be a file or directory")
    files=[]
    with os.scandir(path) as entries:
        for count,entry in enumerate(entries,1):
            if count>limit:
                raise ValueError("release staging directory has too many entries")
            if entry.name.lower().endswith(SUFFIXES):
                files.append(Path(entry.path))
    if not files:
        raise ValueError("no release archives were found")
    return sorted(files)

def archive_main(namespace):
    parser=argparse.ArgumentParser(description=namespace.get("__doc__"))
    parser.add_argument("input",type=Path,help="one release archive or a staging directory")
    args=parser.parse_args()
    files=candidates(args.input,namespace.get("MAX_STAGE_ENTRIES",8192))
    results=[]
    for file in files:
        count,total=namespace["verify"](file)
        results.append(dict(name=file.name,entries=count,uncompressed_bytes=total))
    print("Verified release archives:",len(results))
