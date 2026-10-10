"""`3dsd build`: split (optionally), generate build.ninja, run ninja, report."""

import shutil
import subprocess
from pathlib import Path

from .config import ProjectConfig
from .ninja import generate_ninja
from .objdiff import generate_objdiff, report_progress
from .split import run_split


def _find_ninja() -> str | None:
    """The pip-installed ninja if present, else whatever is on PATH."""
    try:
        from ninja import BIN_DIR  # pylint: disable=import-outside-toplevel  # optional
        return str(Path(BIN_DIR) / 'ninja')
    except ImportError:
        pass
    return shutil.which('ninja')


def run_build(working_dir: Path, jobs: int | None, keep_going: bool,
              targets: list[str] | None, roundtrip: bool = False) -> bool:
    """Run the whole pipeline once; True if ninja succeeded."""
    config = ProjectConfig.load(working_dir)

    # The split exists only to feed the round-trip: the objdiff target is cut
    # from the original binary directly, so a progress build never reads it.
    if roundtrip:
        _print("=== Split ===")
        run_split(config, progress=True)

    _print("=== Ninja ===")
    generate_ninja(config, roundtrip)

    ninja_bin = _find_ninja()
    if not ninja_bin:
        _print("Error: ninja not found. Install it via pip (pip install ninja) "
               "or your system package manager.")
        return False

    _print("=== Build ===")
    cmd = [ninja_bin, '-C', str(working_dir)]
    if jobs is not None:
        cmd += ['-j', str(jobs)]
    if keep_going:
        cmd += ['-k', '0']
    if targets:
        cmd += targets

    result = subprocess.run(cmd, check=False)

    _print("=== Objdiff ===")
    generate_objdiff(config)

    _print("=== Progress ===")
    report_progress(config)

    return result.returncode == 0


def _print(msg: str):
    print(msg, flush=True)
