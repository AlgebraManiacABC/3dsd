import json
import shutil
import subprocess
from pathlib import Path

from .config import ProjectConfig
from .elf import ELF
from .util import Symbol


def _complete_symbols(symbols: list[Symbol], bin_size: int) -> list[Symbol]:
    """Return a symbol list covering every byte, filling gaps with synthetics."""
    sym_dict = {sym.addr: sym for sym in symbols if 0 <= sym.addr < bin_size}
    addrs = sorted(sym_dict.keys())
    result = []
    cur = 0
    idx = 0

    while idx < len(addrs) or cur < bin_size:
        if idx >= len(addrs):
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', bin_size - cur, '.text'))
            break
        elif cur == addrs[idx]:
            sym = sym_dict[cur]
            next_addr = addrs[idx + 1] if idx + 1 < len(addrs) else bin_size
            size = min(sym.size, next_addr - cur)
            result.append(Symbol(cur, sym.name, sym.mode, size, sym.segment))
            cur += size
            idx += 1
        elif cur < addrs[idx]:
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', addrs[idx] - cur, '.text'))
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
        elf = ELF.from_bytes_multi(data, 0, syms)
        out = target_dir / name
        elf.write(out)
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


def report_progress(config: ProjectConfig):
    """Report decomp progress using objdiff-cli."""
    cli = shutil.which('objdiff-cli')
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

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  objdiff-cli produced unparseable output")
        return

    def _fmt(measures: dict, label: str):
        total = int(measures.get('total_code', 0))
        matched = int(measures.get('matched_code', 0))
        matched_pct = float(measures.get('matched_code_percent', 0.0))
        fuzzy_pct = float(measures.get('fuzzy_match_percent', 0.0))
        total_funcs = int(measures.get('total_functions', 0))
        matched_funcs = int(measures.get('matched_functions', 0))
        func_pct = (matched_funcs / total_funcs * 100) if total_funcs else 0
        indent = ' ' * (4 + len(label))
        line = f"  {label}: {matched:,} / {total:,} bytes ({matched_pct:.4f}%)"
        line += f"\n{indent}functions: {matched_funcs:,} / {total_funcs:,} ({func_pct:.2f}%)"
        if fuzzy_pct > matched_pct:
            line += f"\n{indent}fuzzy: {fuzzy_pct:.4f}%"
        print(line)

    units = report.get('units', [])
    for unit in units:
        _fmt(unit.get('measures', {}), unit.get('name', '?'))

    if len(units) > 1:
        _fmt(report.get('measures', {}), 'Total')


def _rel(path: Path, base: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def _posix(p) -> str:
    return str(p).replace('\\', '/')
