import json
import shutil
import subprocess
from pathlib import Path

from .config import ProjectConfig
from .elf import write_target_elf
from .util import Symbol


def _complete_symbols(symbols: list[Symbol], bin_size: int) -> list[Symbol]:
    """Return a symbol list covering every byte, filling gaps with synthetics."""
    sym_dict = {sym.addr: sym for sym in symbols if 0 <= sym.addr < bin_size}
    addrs = sorted(sym_dict.keys())
    result = []
    cur = 0
    idx = 0
    last_segment = '.text'

    while idx < len(addrs) or cur < bin_size:
        if idx >= len(addrs):
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', bin_size - cur, last_segment))
            break
        elif cur == addrs[idx]:
            sym = sym_dict[cur]
            next_addr = addrs[idx + 1] if idx + 1 < len(addrs) else bin_size
            size = min(sym.size, next_addr - cur)
            result.append(Symbol(cur, sym.name, sym.mode, size, sym.segment))
            last_segment = sym.segment
            cur += size
            idx += 1
        elif cur < addrs[idx]:
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', addrs[idx] - cur, last_segment))
            cur = addrs[idx]
        else:
            raise RuntimeError(f"Address tracking error at {cur:08x}")

    return result


def generate_target_elfs(config: ProjectConfig):
    """Wrap each original binary as an ELF with symbols from the CSV."""
    target_dir = config.out_dir / 'objdiff_target'
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in config.binaries:
        data = config.binaries[name].data
        syms = _complete_symbols(config.symbols.get(name, []), len(data))
        out = target_dir / name
        write_target_elf(out, data, syms)
        print(f"  {name}: {len(data):,} bytes, {len(syms)} symbols -> {out}")


def generate_objdiff(config: ProjectConfig):
    """Generate objdiff.json for decomp progress tracking."""
    generate_target_elfs(config)

    units = []
    for name in config.binaries:
        target_path = _rel(config.out_dir / 'objdiff_target' / name, config.working_dir)
        base_elf = config.out_dir / 'objdiff_base' / name
        unit = {
            "name": name,
            "target_path": _posix(target_path),
            "base_path": _posix(_rel(base_elf, config.working_dir)) if base_elf.exists() else None,
            "metadata": {
                "progress_categories": [name],
            },
        }
        units.append(unit)

    objdiff = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "build_target": False,
        "build_base": False,
        "units": units,
        "progress_categories": [{"id": n, "name": n} for n in config.binaries],
    }
    out_path = config.working_dir / 'objdiff.json'
    out_path.write_text(json.dumps(objdiff, indent=2))
    print(f"Generated {out_path}")


_COLUMNS = ('Binary', 'Code bytes', 'Code %', 'Fuzzy %',
            'Functions 100%', 'Func %', 'Data bytes', 'Total bytes', 'Total %')


def measure_row(measures: dict, label: str) -> list[str]:
    """Render one objdiff measures block as a row of table cells.

    Percentages follow objdiff: code is a fraction of total_code, not of the
    whole binary. The total column spans code + data, and only counts matched
    data when objdiff actually reports it.
    """
    tc = int(measures.get('total_code', 0))
    mc = int(measures.get('matched_code', 0))
    code_pct = float(measures.get('matched_code_percent', 0.0))
    fuzzy_pct = float(measures.get('fuzzy_match_percent', 0.0))
    tf = int(measures.get('total_functions', 0))
    mf = int(measures.get('matched_functions', 0))
    td = int(measures.get('total_data', 0))

    has_md = 'matched_data' in measures
    md = int(measures['matched_data']) if has_md else 0

    if td:
        data = f'{md:,} / {td:,}' if has_md else f'{td:,}'
    else:
        data = '-'

    grand_total = tc + td
    grand_matched = mc + md  # md is 0 unless objdiff measured it

    return [
        label,
        f'{mc:,} / {tc:,}' if tc else '-',
        f'{code_pct:.4f}%' if tc else '-',
        f'{fuzzy_pct:.4f}%' if tc else '-',
        f'{mf:,} / {tf:,}' if tf else '-',
        f'{mf / tf * 100:.2f}%' if tf else '-',
        data,
        f'{grand_matched:,} / {grand_total:,}' if grand_total else '-',
        f'{grand_matched / grand_total * 100:.4f}%' if grand_total else '-',
    ]


def format_table(rows: list[list[str]], total_row: list[str] | None = None) -> str:
    """Lay out measure rows as a fixed-width table."""
    all_rows = rows + ([total_row] if total_row else [])
    widths = [len(h) for h in _COLUMNS]
    for row in all_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: list[str]) -> str:
        # First column left-aligned (names), numeric columns right-aligned.
        out = [cells[0].ljust(widths[0])]
        out += [c.rjust(widths[i]) for i, c in enumerate(cells[1:], 1)]
        return '  ' + ' | '.join(out)

    sep = '  ' + '-+-'.join('-' * w for w in widths)
    parts = [line(list(_COLUMNS)), sep]
    parts += [line(r) for r in rows]
    if total_row:
        parts.append(sep)
        parts.append(line(total_row))
    return '\n'.join(parts)


def report_progress(config: ProjectConfig):
    """Report decomp progress using objdiff-cli."""
    cli = shutil.which('objdiff-cli')
    if not cli:
        for name in ('objdiff-cli', 'objdiff-cli.exe'):
            candidate = config.tool_dir / name
            if candidate.exists():
                cli = str(candidate)
                break
    if not cli:
        print("  objdiff-cli not found — install it for progress reporting.")
        return

    result = subprocess.run([cli, 'report', 'generate'],
                            cwd=config.working_dir, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        msg = stderr.splitlines()[-1] if stderr else 'unknown error'
        print(f"  objdiff-cli failed: {msg}")
        return

    # Persist the full report before parsing: only a few summary fields are
    # printed, and the per-symbol detail is useful for inspection and diffing.
    # Written verbatim so it matches what objdiff-cli produces elsewhere (CI).
    report_path = config.out_dir / 'report.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(result.stdout)
    print(f"  Full report: {report_path}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  objdiff-cli produced unparseable output")
        return

    units = report.get('units', [])
    rows = [measure_row(u.get('measures', {}), u.get('name', '?')) for u in units]
    total = measure_row(report.get('measures', {}), 'Total') if len(units) > 1 else None
    print(format_table(rows, total))


def _rel(path: Path, base: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def _posix(p) -> str:
    return str(p).replace('\\', '/')
