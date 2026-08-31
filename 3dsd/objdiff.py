import bisect
import json
import os
import shutil
import struct
import subprocess
import sys
from itertools import zip_longest
from pathlib import Path

from .config import ProjectConfig, sanitize
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


def find_cli(config: ProjectConfig) -> str | None:
    """Locate objdiff-cli on PATH or in the project's tools/ directory."""
    cli = shutil.which('objdiff-cli')
    if cli:
        return cli
    for name in ('objdiff-cli', 'objdiff-cli.exe'):
        candidate = config.tool_dir / name
        if candidate.exists():
            return str(candidate)
    return None


def report_progress(config: ProjectConfig):
    """Report decomp progress using objdiff-cli."""
    cli = find_cli(config)
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


# --- single-symbol diffing --------------------------------------------------

def _unit_extent(config: ProjectConfig, bin_name: str, sym, next_addr: int,
                 widen: bool = True) -> int:
    """How many bytes of the original belong to `sym`.

    The same rule the comparison uses: the declared size, never past the next
    symbol, widened to the compiled length when a literal pool follows.
    """
    size = min(sym.size, next_addr - sym.addr)
    if not widen:
        return size
    compiled = config.compiled_size(bin_name, sanitize(sym.name))
    if compiled and compiled > size and sym.addr + compiled <= next_addr:
        size = compiled
    return size


def build_unit_pair(config: ProjectConfig, bin_name: str, src_key: str,
                    source_map: dict, widen: bool = True) -> tuple[Path, Path] | None:
    """Write a target/base ELF pair covering one source file's symbols.

    The target holds the original bytes of exactly the symbols that file
    claims, laid end to end; the base is that file's object folded through
    base.ld the same way the whole-binary base is. Comparing the pair gives
    per-file totals instead of measuring one file against the whole binary.
    """
    from .elf import write_target_elf

    data = config.binaries[bin_name].data
    by_addr = {s.addr: s for s in config.symbols.get(bin_name, []) if s.addr >= 0}
    addrs = sorted(by_addr)
    mine = sorted((s for a, s in by_addr.items()
                   if sanitize(s.name) in source_map
                   and source_map[sanitize(s.name)][1] == src_key),
                  key=lambda s: s.addr)
    if not mine:
        return None

    # A contiguous slice, not a concatenation. Splicing the symbols together
    # would change the distance between them, and every PC-relative branch
    # inside the file would decode to the wrong target -- objdiff then reports
    # a call as differing when it is identical. Keeping the original spacing
    # costs some bytes and keeps every relative reference intact.
    extents = []
    for s in mine:
        i = bisect.bisect_right(addrs, s.addr)
        nxt = addrs[i] if i < len(addrs) else len(data)
        extents.append((s, _unit_extent(config, bin_name, s, nxt, widen)))
    start = mine[0].addr
    end = max(s.addr + size for s, size in extents)
    blob = data[start:end]

    # Only this file's symbols get entries. Adding the neighbours would let
    # objdiff name more branch targets, but it also drags in the odd-sized
    # symbols a Ghidra export is littered with, and objdiff refuses to
    # disassemble a symbol whose size is not a multiple of two -- one of them
    # anywhere in the unit aborts the whole diff.
    placed = [Symbol(s.addr - start, s.name, s.mode, size, '.text')
              for s, size in extents]

    out_dir = config.out_dir / 'objdiff_units' / bin_name
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = src_key.replace('/', '_')
    target = out_dir / f'{stem}.target.o'
    base = out_dir / f'{stem}.base.o'
    write_target_elf(target, bytes(blob), placed)

    obj = config.obj_path(bin_name, src_key)
    if not obj.exists() or obj.stat().st_size == 0:
        return None
    rsp = out_dir / f'{stem}.rsp'
    rsp.write_text(_posix(obj.resolve()))
    if link_base(config.ld_path().resolve(), base, rsp) != 0:
        return None
    rsp.unlink(missing_ok=True)
    return target, base


def diff_symbol(config: ProjectConfig, name: str) -> int:
    """Show objdiff's instruction-level diff for one symbol."""
    cli = find_cli(config)
    if not cli:
        print("  objdiff-cli not found — put it on PATH or in tools/.")
        return 1

    for bin_name in config.binaries:
        source_map = config.get_source_map(bin_name)
        key = sanitize(name)
        if key not in source_map:
            continue
        src_path, src_key = source_map[key]
        # Not widened here: objdiff disassembles whatever the symbol covers,
        # so including the literal pool renders it as a nonsense instruction
        # and drags the percentage down on a function that does match.
        pair = build_unit_pair(config, bin_name, src_key, source_map, widen=False)
        if pair is None:
            print(f"  {name}: {src_key} has no compiled object to compare against.")
            return 1
        target, base = pair
        return _render_diff(cli, config, bin_name, src_key, key, target, base)

    print(f"  No source claims '{name}'.")
    print(f"  It must be defined by a file under src/ (or a dependency) and "
          f"named in symbols/<binary>.csv.")
    return 1


def _render_diff(cli: str, config: ProjectConfig, bin_name: str, src_key: str,
                 name: str, target: Path, base: Path) -> int:
    out = target.with_suffix('.diff.json')
    r = subprocess.run([cli, 'diff', '-1', str(target), '-2', str(base),
                        '-o', str(out), '--format', 'json', name],
                       capture_output=True, text=True, cwd=config.working_dir)
    if r.returncode != 0 or not out.exists():
        sys.stderr.write(r.stderr)
        return r.returncode or 1
    try:
        doc = json.loads(out.read_text())
    except json.JSONDecodeError:
        print("  objdiff-cli produced unparseable output")
        return 1

    def pick(side):
        return next((s for s in doc.get(side, {}).get('symbols', [])
                     if s.get('name') == name), None)

    left, right = pick('left'), pick('right')
    if left is None or right is None:
        print(f"  {name} is not present on both sides of the diff.")
        return 1

    pct = left.get('match_percent', 0.0)
    print(f"  {left.get('demangled_name') or name}")
    print(f"    {bin_name}  {src_key}  {left.get('size')} bytes  "
          f"{pct:.2f}% match")
    print()

    def text(row):
        # A row with no instruction is objdiff padding one side against the
        # other, where one has an instruction the other does not.
        return ((row or {}).get('instruction') or {}).get('formatted', '')

    li, ri = left.get('instructions', []), right.get('instructions', [])
    width = max([len(text(i)) for i in li] + [8])
    print(f"    {'original':{width}}   compiled")
    print(f"    {'-' * width}   {'-' * width}")
    for a, b in zip_longest(li, ri):
        differs = bool((a or {}).get('diff_kind') or (b or {}).get('diff_kind'))
        mark = ' <<' if differs else ''
        print(f"    {text(a):{width}} | {text(b)}{mark}".rstrip())
    return 0
