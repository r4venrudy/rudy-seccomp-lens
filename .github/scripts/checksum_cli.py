"""Command interface for bounded SHA-256 release verification."""
import argparse
import json
from pathlib import Path

def checksum_directory(path,names):
    if path.is_dir():
        return path
    if path.name not in names or path.is_symlink() or not path.is_file():
        raise ValueError("input must be a staging directory or canonical regular SHA-256 manifest")
    return path.parent

def checksum_main(namespace):
    parser=argparse.ArgumentParser(description="Check release archive SHA-256 entries")
    parser.add_argument("input",type=Path,help="staging directory or its SHA256SUMS manifest")
    parser.add_argument("--json",action="store_true",help="emit a complete deterministic checksum receipt")
    args=parser.parse_args()
    try:
        directory=checksum_directory(args.input,namespace["MANIFEST_NAMES"])
        report=namespace["verify_checksums"](directory)
    except (OSError,ValueError) as error:
        parser.exit(1,f"{error}\n")
    if args.json:print(json.dumps(report,sort_keys=True))
    else:print("Verified release SHA-256 manifest")
