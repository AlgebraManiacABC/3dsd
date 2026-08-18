import json
import shutil
import subprocess
from pathlib import Path

from .config import ProjectConfig
from .elf import ELF
from .util import Symbol, sanitize


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
        source_map = config.get_source_map(name)
        unit = {
            "name": name,
            "target_path": _posix(target_path),
            "base_path": _posix(_rel(config.out_dir / 'objdiff_base' / name, config.working_dir)) if source_map else None,
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
    """Report exact and in-progress (fuzzy) match state per binary."""
    grand_total_bytes = 0
    grand_matching_bytes = 0
    grand_fuzzy_bytes = 0.0
    grand_total_funcs = 0
    grand_matching_funcs = 0
    grand_decompiled = 0
    grand_in_progress = []

    for name in config.binaries:
        symbols = config.symbols.get(name, [])
        source_map = config.get_source_map(name)
        sym_dict = {sym.addr: sym for sym in symbols if sym.addr >= 0}
        addrs = sorted(sym_dict.keys())
        bin_size = len(config.binaries[name].data)

        total_bytes = bin_size
        matching_bytes = 0
        fuzzy_bytes = 0.0
        matching_funcs = 0
        in_progress = []
        total_funcs = 0
        decompiled_funcs = 0

        cur = 0
        addr_idx = 0

        while addr_idx < len(addrs) or cur < bin_size:
            if addr_idx >= len(addrs):
                sym_name = f'{cur:08x}'
                real_name = sym_name
                sym_size = bin_size - cur
                cur += sym_size
                is_symbol = False
            elif cur == addrs[addr_idx]:
                sym = sym_dict[cur]
                sym_name = sanitize(sym.name)
                real_name = sym.name
                next_addr = addrs[addr_idx + 1] if addr_idx + 1 < len(addrs) else bin_size
                sym_size = min(sym.size, next_addr - cur)
                cur += sym_size
                addr_idx += 1
                is_symbol = True
            elif cur < addrs[addr_idx]:
                sym_name = f'{cur:08x}'
                real_name = sym_name
                sym_size = addrs[addr_idx] - cur
                cur = addrs[addr_idx]
                is_symbol = False
            else:
                raise RuntimeError(f"Address tracking error at {cur:08x}")

            if is_symbol:
                total_funcs += 1
            if sym_name not in source_map:
                continue

            decompiled_funcs += 1
            match_stamp = config.link_dir / name / f'{sym_name}.o.match'

            if match_stamp.exists():
                matching_bytes += sym_size
                fuzzy_bytes += sym_size
                matching_funcs += 1
                continue

            _, stem = source_map[sym_name]
            ratio = _fuzzy_ratio(config.build_dir / name / f'{stem}.o',
                                 config.split_dir / name / f'{sym_name}.o',
                                 real_name, sym_name)
            in_progress.append(ratio)
            fuzzy_bytes += sym_size * ratio

        pct = (matching_bytes / total_bytes * 100) if total_bytes else 0
        fuzzy_pct = (fuzzy_bytes / total_bytes * 100) if total_bytes else 0
        func_pct = (matching_funcs / total_funcs * 100) if total_funcs else 0
        indent = ' ' * (4 + len(name))
        line = (f"  {name}: {matching_bytes:,} / {total_bytes:,} bytes ({pct:.4f}%)"
                f"\n{indent}functions: {matching_funcs:,} / {total_funcs:,} ({func_pct:.2f}%),"
                f" {decompiled_funcs:,} with source")
        if in_progress:
            avg = sum(in_progress) / len(in_progress) * 100
            line += (f"\n{indent}fuzzy: {int(fuzzy_bytes):,} bytes ({fuzzy_pct:.4f}%),"
                     f" {len(in_progress)} in progress (avg {avg:.1f}%)")
        print(line)

        grand_total_bytes += total_bytes
        grand_matching_bytes += matching_bytes
        grand_fuzzy_bytes += fuzzy_bytes
        grand_total_funcs += total_funcs
        grand_matching_funcs += matching_funcs
        grand_decompiled += decompiled_funcs
        grand_in_progress.extend(in_progress)

    if len(config.binaries) > 1:
        pct = (grand_matching_bytes / grand_total_bytes * 100) if grand_total_bytes else 0
        fuzzy_pct = (grand_fuzzy_bytes / grand_total_bytes * 100) if grand_total_bytes else 0
        func_pct = (grand_matching_funcs / grand_total_funcs * 100) if grand_total_funcs else 0
        line = (f"  Total: {grand_matching_bytes:,} / {grand_total_bytes:,} bytes ({pct:.4f}%)"
                f"\n         functions: {grand_matching_funcs:,} / {grand_total_funcs:,} ({func_pct:.2f}%),"
                f" {grand_decompiled:,} with source")
        if grand_in_progress:
            avg = sum(grand_in_progress) / len(grand_in_progress) * 100
            line += (f"\n         fuzzy: {int(grand_fuzzy_bytes):,} bytes ({fuzzy_pct:.4f}%),"
                     f" {len(grand_in_progress)} in progress (avg {avg:.1f}%)")
        print(line)

    _report_objdiff_cli(config)


def _fuzzy_ratio(build_o: Path, split_o: Path, real_name: str, sym_name: str) -> float:
    """Fraction of a function's bytes matching the original, reloc sites masked."""
    if not build_o.exists() or build_o.stat().st_size == 0 or not split_o.exists():
        return 0.0
    compiled = ELF.from_section(build_o, real_name)
    if compiled is None and real_name != sym_name:
        compiled = ELF.from_section(build_o, sym_name)
    if compiled is None:
        return 0.0
    split = ELF.from_path(split_o)
    n = min(len(compiled.data), len(split.data))
    denom = max(len(split.data), 1)
    matched = 0
    for i in range(n):
        m = compiled.mask.mask[i] & split.mask.mask[i]
        if (compiled.data[i] & m) == (split.data[i] & m):
            matched += 1
    return matched / denom


def _report_objdiff_cli(config: ProjectConfig):
    """If objdiff-cli is installed, also emit its CI-standard report."""
    cli = shutil.which('objdiff-cli')
    if not cli:
        return
    result = subprocess.run([cli, 'report', 'generate'],
                            cwd=config.working_dir, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        print(f"  (objdiff-cli report failed: {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'no output'})")
        return
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("  (objdiff-cli produced unparseable output)")
        return
    measures = data.get('measures', data)
    fuzzy = measures.get('fuzzy_match_percent')
    matched = measures.get('matched_code_percent')
    if fuzzy is not None or matched is not None:
        parts = []
        if matched is not None:
            parts.append(f"matched {matched:.2f}%")
        if fuzzy is not None:
            parts.append(f"fuzzy {fuzzy:.2f}%")
        print(f"  objdiff-cli: {', '.join(parts)}")


def _rel(path: Path, base: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def _posix(p) -> str:
    return str(p).replace('\\', '/')
