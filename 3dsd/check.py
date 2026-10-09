"""Verifying recreated binaries against the originals."""

import hashlib
from pathlib import Path

from .config import ProjectConfig


def check_binary(original: Path, built: Path) -> bool:
    """SHA-256 hash comparison of two binaries."""
    orig_hash = hashlib.sha256(original.read_bytes()).digest()
    built_hash = hashlib.sha256(built.read_bytes()).digest()
    if orig_hash == built_hash:
        print(f"  MATCH: {built.name}")
        return True
    print(f"  MISMATCH: {built.name}")
    print(f"    Original: {orig_hash.hex()}")
    print(f"    Built:    {built_hash.hex()}")
    return False


def verify_file(original: Path, built: Path, stamp: Path) -> bool:
    """The ninja `verify` step: check one binary and record a pass in `stamp`.

    The stamp is written only on a match and removed on a mismatch, so ninja
    reruns the check until it passes and a failing round-trip fails the build
    instead of leaving a stale "verified" behind.
    """
    if check_binary(original, built):
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(f"{built.name} matches {original.name}\n")
        return True
    stamp.unlink(missing_ok=True)
    return False


def run_check(config: ProjectConfig) -> bool:
    """Check all recreated binaries against originals.

    Reports failure when nothing was checked at all. The recreated binaries
    come from the round-trip, which a plain `3dsd build` no longer runs, so a
    silent pass here would read as "byte-perfect" when it means "not built".
    """
    all_ok = True
    checked = 0
    for name in config.binaries:
        built = config.out_dir / name
        if not built.exists():
            print(f"  SKIP: {name} (not built)")
            continue
        original = next((p for p in config.originals if p.name == name), None)
        if not original:
            print(f"  SKIP: {name} (no original)")
            continue
        checked += 1
        if not check_binary(original, built):
            all_ok = False
    if not checked:
        print(f"  Nothing to check: no recreated binaries in {config.out_dir.name}/.")
        print("  Run '3dsd build --roundtrip' to split, relink and verify.")
        return False
    return all_ok
