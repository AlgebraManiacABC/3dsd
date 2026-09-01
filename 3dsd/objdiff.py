import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from .config import ProjectConfig
from .elf import write_target_elf
from .util import Symbol


def _complete_symbols(symbols: list[Symbol], bin_size: int) -> list[Symbol]:
    """Return a symbol list covering every byte, filling gaps with synthetics.

    Gaps that sit between two `std` symbols inherit the `std` namespace: the
    inter-function alignment padding inside a library region came in from the
    same `.a`, so it is discounted along with the functions around it.
    """
    sym_dict = {sym.addr: sym for sym in symbols if 0 <= sym.addr < bin_size}
    addrs = sorted(sym_dict.keys())
    result = []
    cur = 0
    idx = 0
    last_segment = '.text'
    last_stdlib = False

    def gap_namespace(next_idx: int) -> str:
        """`std` only if the symbols on both sides of the gap are std ones."""
        if not last_stdlib or next_idx >= len(addrs):
            return ''
        return 'std' if sym_dict[addrs[next_idx]].is_stdlib else ''

    while idx < len(addrs) or cur < bin_size:
        if idx >= len(addrs):
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', bin_size - cur,
                                 last_segment, gap_namespace(idx)))
            break
        elif cur == addrs[idx]:
            sym = sym_dict[cur]
            next_addr = addrs[idx + 1] if idx + 1 < len(addrs) else bin_size
            size = min(sym.size, next_addr - cur)
            result.append(Symbol(cur, sym.name, sym.mode, size, sym.segment,
                                 sym.namespace))
            last_segment = sym.segment
            last_stdlib = sym.is_stdlib
            cur += size
            idx += 1
        elif cur < addrs[idx]:
            result.append(Symbol(cur, f'pad_{cur:08x}', '$a', addrs[idx] - cur,
                                 last_segment, gap_namespace(idx)))
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
        std_bytes = sum(s.size for s in syms if s.is_stdlib)
        labelled = len(syms) - sum(1 for s in syms if s.is_stdlib)
        note = f", {std_bytes:,} std bytes discounted" if std_bytes else ""
        print(f"  {name}: {len(data):,} bytes, {labelled} symbols{note} -> {out}")


def generate_objdiff(config: ProjectConfig):
    """Generate objdiff.json for decomp progress tracking."""
    generate_target_elfs(config)

    units = []
    for name in config.binaries:
        target_path = _rel(config.out_dir / 'objdiff_target' / name, config.working_dir)
        base_elf = config.out_dir / 'objdiff_base' / name
        if not base_elf.exists() and config.sources.get(name):
            print(f"  Warning: no base ELF for {name}: the objdiff base link "
                  f"has not run or failed. Progress will read as 0%; run "
                  f"'ninja objdiff' and check the LINK_BASE output.")
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


_RATIO = 'r'   # cell holding "numerator / denominator"
_TEXT = 't'    # cell holding a single value

# A cell is (kind, left, right, tint). `tint` is the completion fraction used
# for colouring, or None for values that do not move during a decomp.


def _text(value: str, tint: float | None = None) -> tuple:
    return (_TEXT, value, '', tint)


def _ratio(num: str, den: str, tint: float | None) -> tuple:
    return (_RATIO, num, den, tint)


def measure_row(measures: dict, label: str) -> list[tuple]:
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

    code_f = (mc / tc) if tc else None
    func_f = (mf / tf) if tf else None
    grand_total = tc + td
    grand_matched = mc + md  # md is 0 unless objdiff measured it
    grand_f = (grand_matched / grand_total) if grand_total else None

    if td and has_md:
        data_cell = _ratio(f'{md:,}', f'{td:,}', md / td)
    elif td:
        # Only a size: objdiff reported no matched-data figure to colour.
        data_cell = _text(f'{td:,}')
    else:
        data_cell = _text('-')

    return [
        _text(label),
        _ratio(f'{mc:,}', f'{tc:,}', code_f) if tc else _text('-'),
        _text(f'{code_pct:.4f}%', code_f) if tc else _text('-'),
        _text(f'{fuzzy_pct:.4f}%', fuzzy_pct / 100) if tc else _text('-'),
        _ratio(f'{mf:,}', f'{tf:,}', func_f) if tf else _text('-'),
        _text(f'{mf / tf * 100:.2f}%', func_f) if tf else _text('-'),
        data_cell,
        _ratio(f'{grand_matched:,}', f'{grand_total:,}', grand_f) if grand_total else _text('-'),
        _text(f'{grand_f * 100:.4f}%', grand_f) if grand_total else _text('-'),
    ]


def _gradient(t: float) -> tuple[int, int, int]:
    """Red at 0, yellow at 0.5, green at 1.

    Exactly zero is dimmed, so an untouched binary is distinguishable at a
    glance from one that has barely started -- at early completion the ramp
    itself is far too shallow to separate them.
    """
    t = max(0.0, min(1.0, t))
    if t == 0.0:
        return (127, 0, 0)
    if t < 0.5:
        return (255, round(510 * t), 0)
    return (round(510 * (1 - t)), 255, 0)


def _paint(text: str, tint: float | None, color: bool) -> str:
    if not color or tint is None:
        return text
    r, g, b = _gradient(tint)
    return f'\x1b[38;2;{r};{g};{b}m{text}\x1b[0m'


def supports_color(stream=None) -> bool:
    """True if ANSI colour is safe to emit on this stream."""
    stream = stream or sys.stdout
    if os.environ.get('NO_COLOR'):
        return False
    if not hasattr(stream, 'isatty') or not stream.isatty():
        return False
    if os.name == 'nt':
        # Legacy consoles print escapes literally unless VT mode is enabled.
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            if not mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
                if not kernel32.SetConsoleMode(
                        handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                    return False
        except Exception:
            return False
    return True


def format_table(rows: list[list[tuple]], total_row: list[tuple] | None = None,
                 color: bool | None = None) -> str:
    """Lay out measure rows as a fixed-width table.

    Ratio cells get their numerator and denominator sized independently so the
    separators line up down the column regardless of magnitude.
    """
    if color is None:
        color = supports_color()

    all_rows = rows + ([total_row] if total_row else [])
    ncols = len(_COLUMNS)

    # Per column: numerator/denominator widths for ratio cells, plus the width
    # any plain cell needs.
    num_w = [0] * ncols
    den_w = [0] * ncols
    flat_w = [len(h) for h in _COLUMNS]
    for row in all_rows:
        for i, (kind, left, right, _) in enumerate(row):
            if kind == _RATIO:
                num_w[i] = max(num_w[i], len(left))
                den_w[i] = max(den_w[i], len(right))
            else:
                flat_w[i] = max(flat_w[i], len(left))

    widths = []
    for i in range(ncols):
        ratio_w = num_w[i] + 3 + den_w[i] if num_w[i] or den_w[i] else 0
        widths.append(max(flat_w[i], ratio_w))

    def render(cell: tuple, i: int) -> str:
        kind, left, right, tint = cell
        if kind == _RATIO:
            body = (' ' * (num_w[i] - len(left)) + _paint(left, tint, color)
                    + ' / ' + right.rjust(den_w[i]))
            visible = num_w[i] + 3 + den_w[i]
        else:
            body = _paint(left, tint, color)
            visible = len(left)
        pad = ' ' * (widths[i] - visible)
        return (left.ljust(widths[i]) if i == 0 else pad + body)

    def line(cells: list[tuple]) -> str:
        return '  ' + ' | '.join(render(c, i) for i, c in enumerate(cells))

    sep = '  ' + '-+-'.join('-' * w for w in widths)
    parts = [line([_text(h) for h in _COLUMNS]), sep]
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


def link_base(ld: Path, output: Path, rsp: Path) -> int:
    """Link the compiled objects into the relocatable base ELF for objdiff.

    Two things have to happen that plain `ld -r` does not do:

    * `base.ld` folds armcc's per-symbol `i.NAME` sections back into
      .text/.rodata/.data/.bss so objdiff can pair them with the target.
      `--force-group-allocation` does the same for the COMDAT groups armcc
      puts its `__ARM_common_*` helpers in; older binutils lack the option,
      so the link is retried without it.
    * armcc emits R_ARM_NONE marker relocations (the printf-variant hints, for
      one). objdiff rejects relocation type 0 outright and refuses to read the
      whole file, so they are stripped afterwards.
    """
    script = Path(__file__).parent / 'base.ld'
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ['-r', '--no-warn-mismatch', '-T', str(script), f'@{rsp}',
            '-o', str(output)]

    result = subprocess.run([str(ld), '--force-group-allocation'] + args,
                            capture_output=True, text=True)
    if result.returncode != 0 and 'force-group-allocation' in result.stderr:
        result = subprocess.run([str(ld)] + args, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        # Ninja leaves a failed command's output in place; a half-written base
        # ELF would be read as a real one on the next progress run.
        output.unlink(missing_ok=True)
        return result.returncode

    removed = strip_none_relocs(output)
    if removed:
        print(f"  {output.name}: stripped {removed} R_ARM_NONE relocation(s)")
    return 0


def strip_none_relocs(path: Path) -> int:
    """Drop every R_ARM_NONE entry from an object's REL sections, in place.

    Kept entries are packed to the front of each section and the section size
    is shrunk; nothing moves, so no offset in the file needs rewriting. The
    few bytes left over sit between sections, unreferenced.
    """
    data = bytearray(path.read_bytes())
    if len(data) < 0x34 or data[:4] != b'\x7fELF':
        return 0
    shoff = struct.unpack_from('<I', data, 0x20)[0]
    shentsize, shnum = struct.unpack_from('<HH', data, 0x2E)

    removed = 0
    for i in range(shnum):
        head = shoff + shentsize * i
        if struct.unpack_from('<I', data, head + 4)[0] != 9:  # SHT_REL
            continue
        off, size = struct.unpack_from('<II', data, head + 0x10)
        entsize = struct.unpack_from('<I', data, head + 0x24)[0] or 8
        kept = bytearray()
        for j in range(size // entsize):
            entry = data[off + j * entsize: off + (j + 1) * entsize]
            if struct.unpack_from('<I', entry, 4)[0] & 0xFF:
                kept += entry
            else:
                removed += 1
        if len(kept) != size:
            data[off:off + len(kept)] = kept
            struct.pack_into('<I', data, head + 0x14, len(kept))

    if removed:
        path.write_bytes(bytes(data))
    return removed
