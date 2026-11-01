"""`3dsd build <dir or file>`: compile and measure part of a project.

A full build compiles every source, links every object into the objdiff
base, cuts a target from every symbol and reports on all of it. When one
file is being worked on, nearly all of that is beside the point, and the
warnings that matter are lost among thousands of others. A partial build:

* compiles only the sources under the given directory, or the given file,
  showing everything the compiler says about each;
* links just those objects into a base of their own (`out/partial/`), split
  as the full base is (datasplit.py);
* cuts a target in which only the symbols those sources define are measured
  -- every other byte stays where it is, so addresses and relocations still
  resolve, but nothing outside the scope counts (`objdiff._apply_scope`);
* reports on that alone, symbol by symbol.

`--symbol` narrows the measurement to one symbol of the file.

Nothing outside `out/partial/` is touched: build.ninja, the project's own
objdiff.json, base and target, and the full report all stay as the last
full build left them.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .compiler import compile_capture, describe, discover_symbols
from .config import ProjectConfig
from .objdiff import build_target, link_base, report_progress, write_objdiff_json
from .util import PipelineError, posix, sanitize

PARTIAL_DIR = 'partial'


def is_project_root(path: Path) -> bool:
    """Whether `path` is a 3dsd project: a cc.yaml beside a symbols/ directory."""
    return (path / 'cc.yaml').is_file() and (path / 'symbols').is_dir()


def find_project_root(path: Path) -> Path | None:
    """The project `path` is or lies in: itself, or the nearest one above it."""
    path = path.resolve()
    start = path if path.is_dir() else path.parent
    for candidate in (start, *start.parents):
        if is_project_root(candidate):
            return candidate
    return None


def run_partial(root: Path, scope: Path, jobs: int | None, symbol: str | None) -> bool:
    """Compile, link, cut and report on the sources under `scope`."""
    config = ProjectConfig.load(root)
    selected = [(bin_name, src) for bin_name, sources in config.sources.items()
                for src in sources if _within(src, scope)]
    if not selected:
        raise PipelineError(f"No compilable source under {scope}.")

    _print(f"=== Compile ({len(selected)} file{'s' if len(selected) != 1 else ''}) ===")
    objects, failed = _compile(config, selected, jobs)

    out_dir = config.out_dir / PARTIAL_DIR
    units = []
    for bin_name, objs in objects.items():
        if not objs:
            continue
        defined: dict[str, str] = {}
        for obj in objs:
            defined.update({name: info.segment
                            for name, info in discover_symbols(obj).items()})
        scope_names = set(defined)
        if symbol is not None:
            if symbol not in defined:
                raise PipelineError(_missing_symbol(symbol, scope, sorted(defined)))
            scope_names = {symbol}
        decompiled = {sanitize(n): seg for n, seg in defined.items() if seg != '.text'}

        _print(f"=== Link ({bin_name}) ===")
        rsp = out_dir / f'{bin_name}.rsp'
        rsp.parent.mkdir(parents=True, exist_ok=True)
        rsp.write_text('\n'.join(f'"{posix(o)}"' for o in objs) + '\n')
        base = out_dir / 'base' / bin_name
        if link_base(config.ld_path(), base, rsp) != 0:
            _print(f"  The base link for {bin_name} failed; nothing to compare.")
            continue

        target = out_dir / 'target' / bin_name
        build_target(config, bin_name, base, target, decompiled, scope_names)
        units.append((bin_name, posix(target.relative_to(out_dir)),
                      posix(base.relative_to(out_dir))))

    if not units:
        return False
    write_objdiff_json(out_dir / 'objdiff.json', units)

    _print("=== Progress ===")
    report_progress(config, project_dir=out_dir, detail=True)
    return not failed


def _within(path: Path, scope: Path) -> bool:
    path = path.resolve()
    return path == scope or scope in path.parents


def _compile(config: ProjectConfig, selected: list[tuple[str, Path]],
             jobs: int | None) -> tuple[dict[str, list[Path]], int]:
    """Compile each selected source, printing all the compiler said about it.

    Returns `{binary: [object]}` for those that compiled, and how many failed;
    a failed compile leaves no object.
    """
    def one(bin_name: str, src: Path):
        key = config.src_key(bin_name, src)
        cc_path, flags = config.get_cc(bin_name, key)
        obj = config.obj_path(bin_name, key)
        rel = src.resolve().relative_to(config.working_dir)
        returncode, text = compile_capture(rel, obj, cc_path, flags, config.working_dir)
        return bin_name, obj, returncode, describe(rel, text, returncode)

    objects: dict[str, list[Path]] = {}
    failed = 0
    workers = jobs or min(32, (os.cpu_count() or 4) * 2)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for bin_name, obj, returncode, report in pool.map(lambda job: one(*job), selected):
            _print(report)
            objects.setdefault(bin_name, [])
            if returncode == 0:
                objects[bin_name].append(obj)
            else:
                failed += 1
    return objects, failed


def _missing_symbol(symbol: str, scope: Path, defined: list[str]) -> str:
    lines = [f"{scope.name} does not define {symbol}."]
    if defined:
        shown = ', '.join(defined[:10])
        more = f", ... ({len(defined) - 10} more)" if len(defined) > 10 else ''
        lines.append(f"  It defines: {shown}{more}")
    return '\n'.join(lines)


def _print(msg: str):
    print(msg, flush=True)
