import subprocess
import sys
from pathlib import Path


def run_build(working_dir: Path, jobs: int | None, keep_going: bool,
              targets: list[str] | None) -> bool:
    from .config import ProjectConfig
    from .split import run_split
    from .ninja import generate_ninja
    from .objdiff import generate_objdiff, report_progress

    config = ProjectConfig.load(working_dir)
    split_dir = config.split_dir
    needs_split = not split_dir.exists() or not any(split_dir.iterdir())
    if needs_split:
        _print("=== Split ===")
        run_split(config, progress=True)

    _print("=== Ninja ===")
    generate_ninja(config)
    generate_objdiff(config)

    try:
        from ninja import BIN_DIR
        ninja_bin = str(Path(BIN_DIR) / 'ninja')
    except ImportError:
        _print("Error: ninja package not installed. Run: pip install ninja")
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

    _print("=== Progress ===")
    report_progress(config)

    return result.returncode == 0


def _print(msg: str):
    print(msg, flush=True)
