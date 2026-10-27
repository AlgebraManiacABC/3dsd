"""`3dsd build`: split (optionally), generate build.ninja, run ninja, report."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .config import ProjectConfig
from .ninja import generate_ninja
from .objdiff import generate_objdiff, report_progress, supports_color
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

    returncode = run_ninja(cmd)

    _print("=== Objdiff ===")
    generate_objdiff(config)

    _print("=== Progress ===")
    report_progress(config)

    return returncode == 0


_STATUS = re.compile(r'^\[\d+/\d+\] ')
_ANSI = re.compile(r'\x1b\[[0-9;]*m')
#: A compile's one-line warning tally (compiler.summarize), colour or not.
_WARN_TALLY = re.compile(r'^(?:\x1b\[[0-9;]*m)?\S.*: \d+ warnings?(?:\x1b\[0m)?$')


def run_ninja(cmd: list[str]) -> int:
    """Run ninja, folding each compile's warning tally into its status line.

    Ninja prints a job's status line and then whatever the job printed, so a
    compile with warnings took two lines -- and before the tally, dozens. Its
    output is read through a pipe instead, and a status line followed by a
    tally becomes one: `[12/3562] src/code.bin/foo.c: 2 warnings`. Anything
    else a job prints, errors above all, follows its status line as usual.

    On a terminal, a status line nothing follows is overwritten by the next,
    as ninja itself does; elsewhere (a CI log) every line is kept.
    """
    tty = supports_color()
    env = dict(os.environ)
    if tty:
        env['CLICOLOR_FORCE'] = '1'  # ninja strips colour from a pipe otherwise
    width = shutil.get_terminal_size().columns - 1
    pending = None   # a status line not yet ended
    live = False     # the cursor sits at the end of a provisional status line
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                          text=True, errors='replace', bufsize=1) as proc:
        for raw in proc.stdout:
            line = raw.rstrip('\n')
            if _STATUS.match(_ANSI.sub('', line)):
                if pending is not None and not tty:
                    _emit(pending, live)
                pending = line
                if tty:
                    sys.stdout.write('\r\x1b[K' + _ANSI.sub('', line)[:width])
                    sys.stdout.flush()
                    live = True
                continue
            if pending is not None and _WARN_TALLY.match(line):
                step = _STATUS.match(_ANSI.sub('', pending)).group(0)
                _emit(step + line, live)
                pending, live = None, False
                continue
            if pending is not None:
                _emit(pending, live)
                pending, live = None, False
            _emit(line, live)
            live = False
        if pending is not None:
            _emit(pending, live)
    return proc.returncode


def _emit(line: str, live: bool):
    """Print a finished line, over the provisional status line if there is one."""
    sys.stdout.write(('\r\x1b[K' if live else '') + line + '\n')
    sys.stdout.flush()


def _print(msg: str):
    print(msg, flush=True)
