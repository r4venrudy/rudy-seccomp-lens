from pathlib import Path
import hashlib
import re

ARCHIVE_SUFFIXES = (".zip", ".jar", ".nupkg", ".whl", ".tar.gz", ".tgz", ".tar.xz")
MANIFEST_NAMES = ("SHA256SUMS", "SHA256SUMS.txt")
MAX_MANIFEST = 1024 * 1024
MAX_MANIFEST_ROWS = 4096
MAX_ASSET_NAME = 255
MAX_STAGE_ENTRIES = 8192
MAX_ASSET = 512 * 1024 * 1024
MAX_CHECKSUM_TOTAL = 2 * 1024 * 1024 * 1024
RESERVED_DEVICES = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}
ROW = re.compile(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)")


def staged_archives(directory: Path) -> set[str]:
    names = set()
    for count, entry in enumerate(directory.iterdir(), 1):
        if count > MAX_STAGE_ENTRIES:
            raise ValueError("release staging directory has too many entries")
        if entry.name.lower().endswith(ARCHIVE_SUFFIXES):
            names.add(entry.name)
    return names


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
    listed = set()
    entries = []
    total_bytes = 0
    text = contents.decode("ascii").replace("\r\n", "\n")
    rows = text.removesuffix("\n").split("\n")
    if len(rows) > MAX_MANIFEST_ROWS:
        raise ValueError("SHA-256 manifest has too many rows")
    for index, row in enumerate(rows, 1):
        match = ROW.fullmatch(row)
        if not match:
            raise ValueError(f"invalid SHA-256 manifest row {index}")
        expected, name = match.groups()
        stem = name.split(".", 1)[0].lower()
        if stem in RESERVED_DEVICES:
            raise ValueError(f"release archive uses a reserved Windows device: {name}")
        if len(name) > MAX_ASSET_NAME:
            raise ValueError(f"release archive name is too long: {name}")
        key = name.lower()
        if key in seen:
            raise ValueError(f"duplicate SHA-256 entry for {name}")
        seen.add(key)
        listed.add(name)

        if not name.endswith(ARCHIVE_SUFFIXES):
            raise ValueError(f"expected a regular release archive for {name}")
        entries.append((name, expected))

    staged = staged_archives(directory)
    unlisted = staged - listed
    if unlisted:
        raise ValueError(f"unlisted release archives: {', '.join(sorted(unlisted))}")
    missing = listed - staged
    if missing:
        raise ValueError(f"expected a regular release archive for {min(missing)}")
    bounded_assets = []
    for name, expected in entries:
        asset = directory / name
        if asset.is_symlink() or not asset.is_file():
            raise ValueError(f"expected a regular release archive for {name}")
        size = asset.stat().st_size
        if size == 0:
            raise ValueError(f"release archive is empty: {name}")
        if size > MAX_ASSET:
            raise ValueError(f"release archive exceeds checksum limit: {name}")
        total_bytes += size
        if total_bytes > MAX_CHECKSUM_TOTAL:
            raise ValueError("staged release exceeds the aggregate checksum limit")
        bounded_assets.append((asset, name, expected, size))

    for asset, name, expected, size in bounded_assets:
        hasher = hashlib.sha256()
        remaining = size
        with asset.open("rb") as stream:
            while chunk := stream.read(min(65536, remaining + 1)):
                if len(chunk) > remaining:
                    raise ValueError(f"release asset changed while hashing: {name}")
                hasher.update(chunk)
                remaining -= len(chunk)
        if remaining:
            raise ValueError(f"release asset changed while hashing: {name}")
        digest = hasher.hexdigest()
        if digest != expected.lower():
            raise ValueError(f"SHA-256 mismatch for {name}")
    if staged_archives(directory) != staged:
        raise ValueError("staged archive inventory changed while hashing")


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
