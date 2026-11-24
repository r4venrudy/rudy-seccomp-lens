"""Command interface for portable release-archive verification."""
import argparse
import os
import json
from pathlib import Path
from contextlib import contextmanager

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

def positive_limit(hard):
    def parse(value):
        try:
            number=int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("expected a positive integer") from error
        if not 1<=number<=hard:
            raise argparse.ArgumentTypeError(f"limit must be between 1 and {hard}")
        return number
    return parse

@contextmanager
def scoped_limits(namespace,values):
    previous={key:namespace[key] for key in values}
    try:
        namespace.update(values)
        yield
    finally:
        namespace.update(previous)

def archive_main(namespace):
    parser=argparse.ArgumentParser(description=namespace.get("__doc__"))
    parser.add_argument("input",type=Path,help="one release archive or a staging directory")
    parser.add_argument("--json",action="store_true",help="emit a complete deterministic JSON audit report")
    parser.add_argument("--max-archive-bytes",type=positive_limit(namespace["MAX_ARCHIVE"]),help="lower the built-in MAX_ARCHIVE limit")
    parser.add_argument("--max-total-bytes",type=positive_limit(namespace["MAX_TOTAL"]),help="lower the built-in MAX_TOTAL limit")
    parser.add_argument("--max-member-bytes",type=positive_limit(namespace["MAX_MEMBER"]),help="lower the built-in MAX_MEMBER limit")
    args=parser.parse_args()
    files=candidates(args.input,namespace.get("MAX_STAGE_ENTRIES",8192))
    overrides={}
    if args.max_archive_bytes is not None: overrides["MAX_ARCHIVE"]=args.max_archive_bytes
    if args.max_total_bytes is not None: overrides["MAX_TOTAL"]=args.max_total_bytes
    if args.max_member_bytes is not None: overrides["MAX_MEMBER"]=args.max_member_bytes
    results=[]
    with scoped_limits(namespace,overrides):
        for file in files:
            count,total=namespace["verify"](file)
            results.append(dict(name=file.name,entries=count,uncompressed_bytes=total))
    if args.json:
        report=dict(schema="rudy.release.archive-report/v1",archive_count=len(results),archives=results,
                    entries=sum(row["entries"] for row in results),uncompressed_bytes=sum(row["uncompressed_bytes"] for row in results))
        print(json.dumps(report,sort_keys=True))
    else:
        print("Verified release archives:",len(results))
