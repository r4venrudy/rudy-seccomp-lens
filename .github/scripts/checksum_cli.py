"""Command interface for bounded SHA-256 release verification."""
import argparse
import json
from pathlib import Path
from release_cli import positive_limit,scoped_limits

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
    parser.add_argument("--max-asset-bytes",type=positive_limit(namespace["MAX_ASSET"]),help="lower the per-archive hashing byte limit")
    parser.add_argument("--max-total-bytes",type=positive_limit(namespace["MAX_CHECKSUM_TOTAL"]),help="lower the aggregate hashing byte limit")
    args=parser.parse_args()
    limits={}
    if args.max_asset_bytes is not None:limits["MAX_ASSET"]=args.max_asset_bytes
    if args.max_total_bytes is not None:limits["MAX_CHECKSUM_TOTAL"]=args.max_total_bytes
    try:
        directory=checksum_directory(args.input,namespace["MANIFEST_NAMES"])
        with scoped_limits(namespace,limits):
            report=namespace["verify_checksums"](directory)
    except (OSError,ValueError) as error:
        parser.exit(1,f"{error}\n")
    if args.json:print(json.dumps(report,sort_keys=True))
    else:print("Verified release SHA-256 manifest")
