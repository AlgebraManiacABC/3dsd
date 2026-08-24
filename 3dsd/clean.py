import shutil
from pathlib import Path

from .config import BUILD_DIR, SPLIT_DIR, LINK_DIR, OUT_DIR

# Each target maps to the paths it removes, relative to the working directory.
# Paths that do not exist are skipped silently.
_TARGETS: dict[str, list[str]] = {
    'build': [BUILD_DIR],
    'split': [SPLIT_DIR],
    'link': [LINK_DIR],
    'out': [OUT_DIR],
    'ninja': ['build.ninja', '.ninja_log', '.ninja_deps'],
    'objdiff': ['objdiff.json'],
}

# Everything except 'split': re-splitting a large binary costs minutes, so it
# is opt-in via an explicit target or 'all'.
_DEFAULT = ['build', 'link', 'out', 'ninja', 'objdiff']

_ALL = list(_TARGETS)


def _resolve(targets: list[str]) -> list[str]:
    """Expand the requested targets, or raise ValueError on an unknown name."""
    if not targets:
        return list(_DEFAULT)
    if 'all' in targets:
        return list(_ALL)
    unknown = [t for t in targets if t not in _TARGETS]
    if unknown:
        valid = ', '.join(_ALL + ['all'])
        raise ValueError(
            f"Unknown clean target(s): {', '.join(unknown)}\n  Valid targets: {valid}")
    # Preserve _ALL's order and drop duplicates.
    return [t for t in _ALL if t in targets]


def run_clean(working_dir: Path, targets: list[str], dry_run: bool = False) -> bool:
    """Remove generated build output. Returns False on an unknown target."""
    try:
        selected = _resolve(targets)
    except ValueError as e:
        print(f"  {e}")
        return False

    root = working_dir.resolve()
    removed = 0

    for name in selected:
        for rel in _TARGETS[name]:
            path = working_dir / rel
            if not path.exists():
                continue

            # Never follow a symlink or misconfigured path out of the project.
            resolved = path.resolve()
            if root not in resolved.parents:
                print(f"  SKIP (outside project): {path}")
                continue

            print(f"  {'Would remove' if dry_run else 'Removing'} {rel}")
            if not dry_run:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            removed += 1

    if not removed:
        print("  Nothing to clean.")
        return True

    if 'split' in selected:
        print("  Note: split output removed — the next build will re-split "
              "the originals, which takes several minutes.")
    if not dry_run and ('build' in selected or 'ninja' in selected):
        print("  Note: run '3dsd ninja .' (or any '3dsd build .') before "
              "invoking ninja directly.")

    return True
