import shutil
import subprocess
import sys
from pathlib import Path


def _find_ninja() -> str | None:
    try:
        from ninja import BIN_DIR
        return str(Path(BIN_DIR) / 'ninja')
    except ImportError:
        pass
    return shutil.which('ninja')


def run_build(working_dir: Path, jobs: int | None, keep_going: bool,
              targets: list[str] | None, roundtrip: bool = False) -> bool:
    from .config import ProjectConfig
    from .split import run_split
    from .ninja import generate_ninja
    from .objdiff import generate_objdiff, report_progress

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
        _print("Error: ninja not found. Install it via pip (pip install ninja) or your system package manager.")
        return False

    _print("=== Build ===")
    cmd = [ninja_bin, '-C', str(working_dir)]
    if jobs is not None:
        cmd += ['-j', str(jobs)]
    if keep_going:
        cmd += ['-k', '0']
    if targets:
        cmd += targets

    result = subprocess.run(cmd)

    _print("=== Objdiff ===")
    generate_objdiff(config)

    _print("=== Progress ===")
    report_progress(config)

    return result.returncode == 0


def _print(msg: str):
    print(msg, flush=True)
