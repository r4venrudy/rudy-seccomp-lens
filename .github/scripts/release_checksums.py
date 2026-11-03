from pathlib import Path
import hashlib
import re

ARCHIVE_SUFFIXES = (".zip", ".jar", ".nupkg", ".whl", ".tar.gz", ".tgz", ".tar.xz")
MANIFEST_NAMES = ("SHA256SUMS", "SHA256SUMS.txt")
MAX_MANIFEST = 1024 * 1024
MAX_ASSET = 512 * 1024 * 1024
ROW = re.compile(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)")


def verify_checksums(directory: Path) -> None:
    candidates = [directory / name for name in MANIFEST_NAMES]
    manifests = [p for p in candidates if p.exists() or p.is_symlink()]
    if len(manifests) != 1 or manifests[0].is_symlink() or not manifests[0].is_file():
        raise ValueError("expected exactly one regular SHA-256 manifest")

    with manifests[0].open("rb") as stream:
        contents = stream.read(MAX_MANIFEST + 1)
    if not contents or len(contents) > MAX_MANIFEST:
        raise ValueError("SHA-256 manifest is empty or oversized")

    seen = set()
    for index, row in enumerate(contents.decode("ascii").splitlines(), 1):
        match = ROW.fullmatch(row)
        if not match:
            raise ValueError(f"invalid SHA-256 manifest row {index}")
        expected, name = match.groups()
        key = name.lower()
        if key in seen:
            raise ValueError(f"duplicate SHA-256 entry for {name}")
        seen.add(key)

        asset = directory / name
        if not name.endswith(ARCHIVE_SUFFIXES) or asset.is_symlink() or not asset.is_file():
            raise ValueError(f"expected a regular release archive for {name}")
        if asset.stat().st_size > MAX_ASSET:
            raise ValueError(f"release archive exceeds checksum limit: {name}")
        with asset.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected.lower():
            raise ValueError(f"SHA-256 mismatch for {name}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Check release archive SHA-256 entries")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        verify_checksums(args.directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print("Verified release SHA-256 manifest")
