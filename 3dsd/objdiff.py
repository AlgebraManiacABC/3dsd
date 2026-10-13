"""objdiff integration: target ELFs, objdiff.json, the base link and progress."""

import bisect
import ctypes
import itertools
import json
import os
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import ProjectConfig
from .ctrtype import CRO, CTRBinary
from .datasplit import POOL_SEGMENT, pool_section, split_data_objects, split_sections_of
from .elf import SectionHeaderType, write_target_elf
from .reloc import BaseObject, RelocRecovery, read_base
from .util import Symbol, posix, sanitize

_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11


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
        if cur == addrs[idx]:
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


#: Segments whose symbols objdiff can meaningfully diff against a compiled base.
DATA_SEGMENTS = ('.rodata', '.data')

#: Where undecompiled data goes. The base ELF never has a section by this name,
#: so objdiff pairs nothing and never diffs these bytes. That matters more than
#: it sounds: objdiff's data diff is quadratic in section length -- measured at
#: 0.3 s for 8 KB, 51 s for 128 KB, 210 s for 256 KB -- so leaving New Leaf's
#: whole 1.13 MB .rodata paired costs over an hour, while the few KB actually
#: decompiled costs milliseconds. Unnaming the symbols (as `std` does) would
#: fix the percentages but not the cost, because the bytes would still be in
#: the paired section.
#:
#: The name deliberately is not `.rodata.something`: objdiff folds a dotted
#: suffix back into its parent section, the way `-ffunction-sections` output is
#: meant to be read, so `.rodata.undecompiled` was silently counted as .rodata
#: and diffed anyway. It has to be a section name of its own, matching the
#: invented `.rwdata` that `base.ld` already relies on.
SKIP_SEGMENT = '.undecompiled'


def _route_data(symbols: list[Symbol], decompiled: dict[str, str],
                split: dict[str, str] | None = None,
                pools: set[str] | None = None) -> list[Symbol]:
    """Send each data symbol to the section that lets it pair, or out of the way.

    A decompiled object takes the section armcc put the base's copy in, not the
    one the CSV names. objdiff pairs within a section, and the two disagree
    often: whether a table is `const` decides `.rodata` against `.data`, and an
    export has no way to know. Following the CSV instead would leave the halves
    in different sections, pairing nothing while looking entirely healthy.

    An object the base has given a section of its own (`split`, see
    datasplit.py) goes to the section of the same name, so it pairs, and
    scores, alone.

    A `$d` label in .text is data too, never a function. Every one between a
    function whose compiled pool the base has split out (`pools`) and the next
    code symbol belongs to that function's literal pool and goes to the same
    `.pool:<function>` section, so the two are compared; any other goes with
    the undecompiled data.

    Applied before the gaps are filled, so the padding between two undecompiled
    data objects inherits the skipped segment too and stays out of the diff.
    """
    split = split or {}
    owners = _pool_owners(symbols, pools or set())
    out = []
    for sym in symbols:
        if sym.segment == '.text' and sym.mode == '$d':
            # Data inside the code segment -- a literal pool, a jump table --
            # labelled as such in the CSV.
            owner = owners.get(id(sym))
            section = pool_section(owner) if owner is not None else SKIP_SEGMENT
            out.append(Symbol(sym.addr, sym.name, sym.mode, sym.size,
                              section, sym.namespace))
            continue
        if sym.segment not in DATA_SEGMENTS:
            out.append(sym)
            continue
        section = decompiled.get(sanitize(sym.name), SKIP_SEGMENT)
        if section != SKIP_SEGMENT:
            section = split.get(sym.name, section)
        out.append(Symbol(sym.addr, sym.name, sym.mode, sym.size,
                          section, sym.namespace))
    return out


def _pool_owners(symbols: list[Symbol], pools: set[str]) -> dict[int, str]:
    """`{id(label): function}` for each `$d` label in .text that follows a
    function in `pools`, up to the next code symbol."""
    owners: dict[int, str] = {}
    text = sorted((s for s in symbols if s.segment == '.text'), key=lambda s: s.addr)
    owner = None
    for sym in text:
        if sym.mode in ('$a', '$t'):
            owner = sym.name if sym.name in pools else None
        elif owner is not None:
            owners[id(sym)] = owner
    return owners


def _keep_text_gaps(symbols: list[Symbol], csv: list[Symbol]) -> list[Symbol]:
    """Settle the gaps after `$d` labels in .text.

    A gap between two labels of the same pool is part of that pool: the
    compiled pool runs unbroken from its first word to its last, so leaving
    the gap out would make the two differ by its bytes. Any other gap after a
    label stays code. It would otherwise take the label's data segment and
    quietly count whatever unnamed bytes follow -- alignment, or code nobody
    has labelled -- as data; what they are is for the CSV to say.

    Runs after `_skip_data_padding`, which would send the pool's own gaps
    to the undecompiled data.
    """
    label_ends = {s.addr + s.size for s in csv if s.segment == '.text' and s.mode == '$d'}
    out = list(symbols)
    for i, sym in enumerate(out):
        if not sym.name.startswith('pad_') or sym.addr not in label_ends:
            continue
        before = out[i - 1].segment if i > 0 else None
        after = out[i + 1].segment if i + 1 < len(out) else None
        in_pool = before is not None and before == after and before.startswith(POOL_SEGMENT)
        segment = before if in_pool else '.text'
        out[i] = Symbol(sym.addr, sym.name, sym.mode, sym.size, segment, sym.namespace)
    return out


def _skip_data_padding(symbols: list[Symbol]) -> list[Symbol]:
    """Keep gap filler out of the paired data sections.

    A gap inherits the segment of the symbol before it, so one decompiled table
    near the start of the data region would drag every following unnamed byte
    into `.rodata` -- on ikachan that is 203,776 bytes of padding, which is the
    quadratic cost this whole arrangement exists to avoid. Padding is by
    definition not decompiled, so it belongs with the rest of the skipped data.
    """
    out = []
    for sym in symbols:
        if _is_data(sym.segment) and sym.name.startswith('pad_'):
            out.append(Symbol(sym.addr, sym.name, sym.mode, sym.size,
                              SKIP_SEGMENT, sym.namespace))
        else:
            out.append(sym)
    return out


def _is_data(segment: str) -> bool:
    """Whether a segment pairs with base data: `.rodata`, `.data`, or one object's own."""
    parent = segment.partition(':')[0]
    return segment in DATA_SEGMENTS or parent in DATA_SEGMENTS or parent == POOL_SEGMENT


def generate_target_elfs(config: ProjectConfig):
    """Wrap each original binary as an ELF with symbols from the CSV.

    Where the base ELF has already been linked, the target also gets the
    relocations its compiled twin implies (see reloc.py); without them a
    function that calls anything can never match.
    """
    target_dir = config.out_dir / 'objdiff_target'
    target_dir.mkdir(parents=True, exist_ok=True)
    for name, binary in config.binaries.items():
        data = binary.data
        decompiled = config.get_decompiled_data(name)
        csv, marks = _place_markers(name, config.symbols.get(name, []),
                                    config.markers.get(name, []), len(data), binary.base_addr)
        base_path = config.out_dir / 'objdiff_base' / name
        base = read_base(base_path.read_bytes()) if base_path.exists() else None
        split = split_sections_of(base.names) if base is not None else {}
        pools = {n.partition(':')[2] for n in base.names
                 if n.startswith(POOL_SEGMENT + ':')} if base is not None else set()
        raw = _route_data(csv, decompiled, split, pools)
        syms = _keep_text_gaps(_skip_data_padding(_complete_symbols(raw, len(data))), csv)
        _warn_unnamed(name, syms, binary.base_addr,
                      set(base.by_name) if base is not None else set())
        if base is not None:
            syms, cut = _cut_pools(syms, marks, set(base.names))
            # A cut function's markers are spent: its pieces are its sections.
            marks.mapping = [m for m in marks.mapping
                             if not any(a <= m[0] < b for a, b in cut)]
        data, relocs, mapping, rel_note = _recover_relocs(base, binary, csv, syms, marks)
        out = target_dir / name
        write_target_elf(out, data, syms, relocs, marks.mapping + mapping)
        std_bytes = sum(s.size for s in syms if s.is_stdlib)
        labelled = len(syms) - sum(1 for s in syms if s.is_stdlib)
        note = f", {std_bytes:,} std bytes discounted" if std_bytes else ""
        print(f"  {name}: {len(data):,} bytes, {labelled} symbols{note}{rel_note} -> {out}")


@dataclass
class _Markers:
    """What a CSV's mapping rows contribute to the target."""
    #: `(addr, '$a'|'$t'|'$d')` for every marker inside a symbol.
    mapping: list[tuple[int, str]] = field(default_factory=list)
    #: Functions with at least one marker inside them.
    functions: set[str] = field(default_factory=set)
    #: `{function: [(start, end, mode)]}`: the extent of each marker inside it.
    inner: dict[str, list[tuple[int, int, str]]] = field(default_factory=dict)


def _place_markers(name: str, csv: list[Symbol], markers: list[Symbol],  # pylint: disable=too-many-locals
                   bin_size: int, base_addr: int) -> tuple[list[Symbol], _Markers]:
    """Sort a CSV's mapping rows into markers inside symbols and trailing pools.

    A marker inside a symbol becomes a mapping symbol in the target, so a
    mid-function pool decodes as `.word` rows, as armcc's own `$d` makes it on
    the compiled side. A `$d` outside every symbol is data with no name --
    typically the literal pool after a function, which armcc leaves outside
    the function's symbol -- so it is returned as a `$d` symbol of its own
    (`pool_<address>`), for `_route_data` to pair with the function before it.

    A marker runs until the next one or the end of its symbol (or, outside
    any, the next symbol). A `$d` whose Size ends sooner ends there, and the
    unnamed bytes after it are taken for code, never as more of the pool. A
    Size that runs past the next marker or symbol is reported and cut short.
    """
    out = _Markers()
    extents = sorted((s.addr, s.addr + s.size, s.name) for s in csv
                     if s.segment == '.text' and s.size > 0 and 0 <= s.addr < bin_size)
    modes = {s.name: s.mode for s in csv if s.segment == '.text'}
    starts = [e[0] for e in extents]
    all_starts = sorted(s.addr for s in csv if 0 <= s.addr < bin_size)
    marks = sorted((m for m in markers if 0 <= m.addr < bin_size), key=lambda m: m.addr)
    trailing = []
    overruns = []
    code_mode: dict[str, str] = {}   # the mode a function's code is in, so far
    for k, mark in enumerate(marks):
        nxt = marks[k + 1].addr if k + 1 < len(marks) else bin_size
        i = bisect.bisect_right(starts, mark.addr) - 1
        inside = i >= 0 and mark.addr < extents[i][1]
        if inside:
            limit = min(nxt, extents[i][1])
        else:
            j = bisect.bisect_right(all_starts, mark.addr)
            limit = min(nxt, all_starts[j] if j < len(all_starts) else bin_size)
        end = limit
        if mark.size and mark.size > limit - mark.addr:
            overruns.append(f"{base_addr + mark.addr:08x} {mark.mode}: Size {mark.size:#x}, "
                            f"but the next marker or symbol is {limit - mark.addr:#x} away")
        elif mark.size and mark.mode == '$d':
            # Data ends where the CSV says it does. What follows, unnamed, is
            # taken for code -- a pool is never stretched over it.
            end = mark.addr + mark.size
        if inside:
            func = extents[i][2]
            out.mapping.append((mark.addr, mark.mode))
            out.functions.add(func)
            out.inner.setdefault(func, []).append((mark.addr, end, mark.mode))
            if mark.mode != '$d':
                code_mode[func] = mark.mode
            elif end < limit:
                resume = code_mode.get(func, modes.get(func, '$a'))
                out.mapping.append((end, resume))
                out.inner[func].append((end, limit, resume))
        elif mark.mode == '$d':
            trailing.append(Symbol(mark.addr, f'pool_{base_addr + mark.addr:08x}', '$d',
                                   end - mark.addr, mark.segment, mark.namespace))
    if overruns:
        print(f"  Warning: {name}: {len(overruns):,} mapping row(s) whose Size runs past the "
              f"next marker or symbol; cut short there:")
        for line in overruns[:5]:
            print(f"    {line}")
        if len(overruns) > 5:
            print(f"    ... and {len(overruns) - 5:,} more")
    return csv + trailing, out


def _cut_pools(syms: list[Symbol], marks: _Markers,
               base_sections: set[str]) -> tuple[list[Symbol], list[tuple[int, int]]]:
    """Cut the literal pools out of the middle of each decompiled function.

    A pool inside a function is data, as one after it is, so it is measured
    as data: the function's code ranges go to `.text:<function>`, laid end to
    end, and its pools join its trailing pool in `.pool:<function>`. The base
    does the same from armcc's own mapping symbols (datasplit.py), so the
    function then compares instruction for instruction and the pools word
    for word. The boundaries are the CSV's mapping rows; a function the base
    did not cut stays whole.

    Only the first code piece carries the function's name; the writer gives
    it the size of all of them. Returns the symbols and the extent of every
    function cut.
    """
    out = []
    cut = []
    for sym in syms:
        runs = marks.inner.get(sym.name) if sym.segment == '.text' else None
        code_section = f'.text:{sym.name}'
        if sym.segment != '.text' or code_section not in base_sections:
            out.append(sym)
            continue
        if not runs or not any(mode == '$d' for _, _, mode in runs):
            # armcc's version has pools inside but the CSV marks none: kept
            # whole, it still pairs (and is reported) until the rows are added.
            out.append(Symbol(sym.addr, sym.name, sym.mode, sym.size, code_section,
                              sym.namespace))
            continue
        cuts = sorted(runs)
        pieces = []
        cur, mode = sym.addr, sym.mode
        for start, end, kind in cuts:
            if start > cur:
                pieces.append((cur, start - cur, mode, code_section))
            if kind == '$d':
                pieces.append((start, end - start, '$d', pool_section(sym.name)))
            else:
                pieces.append((start, end - start, kind, code_section))
                mode = kind
            cur = max(cur, end)
        if cur < sym.addr + sym.size:
            pieces.append((cur, sym.addr + sym.size - cur, mode, code_section))
        cut.append((sym.addr, sym.addr + sym.size))
        named = False
        for addr, size, kind, section in pieces:
            name = ''
            if section == code_section and not named:
                name, named = sym.name, True
            out.append(Symbol(addr, name, kind, size, section, sym.namespace))
    return out, cut


def _warn_unmarked(name: str, syms: list[Symbol], base: BaseObject, marked: set[str],
                   base_addr: int):
    """Report decompiled functions with data inside that the CSV does not mark.

    armcc marks a mid-function literal pool with `$d`. Without the matching
    mapping rows in the CSV, the target has to infer that pool from the
    function's own pc-relative loads; only the CSV can say for certain.
    """
    cut = {n.partition(':')[2] for n in base.names if n.startswith('.text:')}
    missing = [s for s in syms if s.segment.partition(':')[0] == '.text' and s.name
               and s.name not in marked
               and (s.name in cut or ((twin := base.twin(s.name, '.text')) is not None
                                      and base.has_inner_data(twin)))]
    if not missing:
        return
    print(f"  Warning: {name}: {len(missing):,} decompiled function(s) hold data (a "
          f"literal pool) the CSV does not mark; add $d/$a/$t mapping rows:")
    for sym in missing[:5]:
        print(f"    {base_addr + sym.addr:08x} {sym.name}")
    if len(missing) > 5:
        print(f"    ... and {len(missing) - 5:,} more")


def _warn_unnamed(name: str, syms: list[Symbol], base_addr: int, compiled: set[str]):
    """Report the bytes the symbol CSV leaves unnamed.

    The pipeline cannot tell what such a region is -- ARM code, Thumb code,
    or data such as a literal pool -- so it is written as an unnamed `pad_`
    symbol: code in .text, where objdiff counts it as an unmatched function,
    or undecompiled data elsewhere. Only the CSV can say otherwise, so the
    gaps are listed for it to be filled in. Those right after a compiled
    function come first: they are most often its literal pool, which objdiff
    then never compares.
    """
    pads = [s for s in syms if s.name.startswith('pad_') and not s.is_stdlib]
    if not pads:
        return
    code = [p for p in pads if p.segment == '.text']
    code_bytes = sum(p.size for p in code)
    data_bytes = sum(p.size for p in pads) - code_bytes
    print(f"  Warning: {name}: {len(pads):,} region(s) the symbol CSV does not name "
          f"({code_bytes:,} bytes counted as code, {data_bytes:,} as data). "
          f"Label them as $a/$t/$d in the CSV.")
    previous = {}
    for before, sym in itertools.pairwise(syms):
        previous[sym.addr] = before
    after_compiled = [p for p in code
                      if previous.get(p.addr) is not None and previous[p.addr].name in compiled]
    if after_compiled:
        print(f"    {len(after_compiled):,} directly follow a decompiled function "
              f"(likely its literal pool, left uncompared):")
        for pad in after_compiled[:5]:
            print(f"      {base_addr + pad.addr:08x} +{pad.size:<5} after "
                  f"{previous[pad.addr].name}")
        if len(after_compiled) > 5:
            print(f"      ... and {len(after_compiled) - 5:,} more")


def _recover_relocs(base: BaseObject | None, binary: CTRBinary,  # pylint: disable=too-many-arguments,too-many-positional-arguments
                    csv: list[Symbol], syms: list[Symbol], marks: "_Markers"):
    """`(data, relocs, mapping, note)`: the target's bytes, relocations and
    literal-pool mapping symbols, recovered against its base."""
    if base is None:
        return binary.data, [], [], ''
    # A CRO's pointers are fixed up at load time, so its pool words hold no
    # addresses to look up; its branches are pc-relative and still resolve.
    recovery = RelocRecovery(binary.data, csv, base, binary.base_addr,
                             pointers=not isinstance(binary.binary, CRO))
    recovery.marked = marks.functions
    data, relocs = recovery.run(syms)
    _warn_unmarked(binary.name, syms, base, marks.functions, binary.base_addr)
    note = f", {len(relocs):,} relocations"
    if recovery.unresolved:
        note += f" ({recovery.unresolved:,} references reach no CSV symbol)"
    return data, relocs, recovery.mapping, note


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
            "target_path": posix(target_path),
            "base_path": posix(_rel(base_elf, config.working_dir)) if base_elf.exists() else None,
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


_COLUMNS = ('Binary', 'Code bytes', 'Code %', 'Fuzzy Code %',
            'Data bytes', 'Data %', 'Fuzzy Data %', 'Total bytes', 'Total %')


_RATIO = 'r'   # cell holding "numerator / denominator"
_TEXT = 't'    # cell holding a single value

# A cell is (kind, left, right, tint). `tint` is the completion fraction used
# for colouring, or None for values that do not move during a decomp.


def _text(value: str, tint: float | None = None) -> tuple:
    return (_TEXT, value, '', tint)


def _ratio(num: str, den: str, tint: float | None) -> tuple:
    return (_RATIO, num, den, tint)


def _percent(value: float, tint: float | None) -> tuple:
    """A percentage cell, shown as '-' when it is an absolute zero.

    A screenful of `0.0000%` says nothing that a dash does not, and it buries
    the rows that have actually moved. The dash keeps the zero tint, so it
    still reads as red-for-nothing rather than as the untinted dash used for
    a figure that does not apply at all -- an unstarted binary and one with
    no data section stay distinguishable.

    Only an exact zero is collapsed. A value that merely rounds to `0.0000%`
    is real progress and keeps its digits.
    """
    if value == 0.0:
        return _text('-', 0.0)
    return _text(f'{value:.4f}%', tint)


def data_fuzzy_percent(sections: list[dict], total_data: int) -> float | None:
    """Size-weighted mean of the fuzzy percent over the data sections.

    objdiff reports no fuzzy figure for data: `fuzzy_match_percent` in the
    measures covers code only, because report generation `continue`s on a data
    section before reaching the per-symbol loop that accumulates it. The
    per-section percentages are reported though, so the data equivalent is
    their weighted mean -- which is what `matched_data` deliberately is not.
    `matched_data` credits a section only at exactly 100%, so a section one
    symbol short contributes nothing; this says how far along it is.

    "Data" here is every section that is not code, which for our synthesized
    targets means .rodata, .data and whatever the undecompiled remainder is
    routed to. The sizes are checked against objdiff's own `total_data` and
    None is returned when they disagree, rather than reporting a percentage of
    the wrong denominator.
    """
    weighted = 0.0
    size = 0
    for section in sections:
        if str(section.get('name', '')).startswith('.text'):
            continue
        sec_size = int(section.get('size', 0))
        weighted += float(section.get('fuzzy_match_percent', 0.0)) * sec_size
        size += sec_size
    if not size or (total_data and size != total_data):
        return None
    return weighted / size


def measure_row(measures: dict, label: str,
                sections: list[dict] | None = None) -> list[tuple]:
    """Render one objdiff measures block as a row of table cells.

    Percentages follow objdiff: code is a fraction of total_code and data of
    total_data, neither of the whole binary. Both get a strict column (bytes
    that match exactly) and a fuzzy one (how close everything is). The total
    column spans code + data, and only counts matched data when objdiff
    actually reports it.
    """
    tc = int(measures.get('total_code', 0))
    mc = int(measures.get('matched_code', 0))
    code_pct = float(measures.get('matched_code_percent', 0.0))
    fuzzy_pct = float(measures.get('fuzzy_match_percent', 0.0))
    td = int(measures.get('total_data', 0))

    # A zero matched_data is absent from the JSON rather than present as 0:
    # the report is a protobuf, and proto3 omits default-valued fields. So an
    # absent field means none of the data matches, not that it went unmeasured
    # -- reporting it as '-' understated a real 0.0000%.
    md = int(measures.get('matched_data', 0))
    data_pct = float(measures.get('matched_data_percent', 0.0))
    data_fuzzy = data_fuzzy_percent(sections or [], td)

    code_f = (mc / tc) if tc else None
    data_f = (md / td) if td else None
    grand_total = tc + td
    grand_matched = mc + md  # md is 0 unless objdiff measured it
    grand_f = (grand_matched / grand_total) if grand_total else None

    # A binary with no data section of its own -- every .cro here -- still
    # tints its data cells as zero, so a row that has not moved reads as one
    # colour instead of leaving the three data columns as the only untinted
    # cells in it. The untinted dash is kept for the one case that really is
    # unknown rather than zero: data exists but its section sizes disagree
    # with objdiff's total, so data_fuzzy_percent declined to guess.
    absent = _text('-', 0.0)
    unknown = _text('-')

    data_cell = _ratio(f'{md:,}', f'{td:,}', data_f) if td else absent

    return [
        _text(label),
        _ratio(f'{mc:,}', f'{tc:,}', code_f) if tc else absent,
        _percent(code_pct, code_f) if tc else absent,
        _percent(fuzzy_pct, fuzzy_pct / 100) if tc else absent,
        data_cell,
        _percent(data_pct, data_f) if td else absent,
        _percent(data_fuzzy, data_fuzzy / 100) if data_fuzzy is not None
        else (unknown if td else absent),
        _text(f'{grand_total:,}') if grand_total else unknown,
        _percent(grand_f * 100, grand_f) if grand_total else absent,
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
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
            mode = ctypes.c_ulong()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            vt_mode = mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING
            if vt_mode != mode.value and not kernel32.SetConsoleMode(handle, vt_mode):
                return False
        except (AttributeError, OSError):
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

    # Pretty-printed so the saved report.json is readable and diffs line by
    # line; json.loads below does not care either way.
    result = subprocess.run([cli, 'report', 'generate', '--format', 'json-pretty'],
                            cwd=config.working_dir, capture_output=True, text=True,
                            check=False)
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
    rows = [measure_row(u.get('measures', {}), u.get('name', '?'),
                        u.get('sections', [])) for u in units]
    # The report's own measures block carries no sections, so the total row
    # gets every unit's pooled -- the weighted mean over all of them is the
    # same calculation at a larger scale.
    all_sections = [s for u in units for s in u.get('sections', [])]
    total = (measure_row(report.get('measures', {}), 'Total', all_sections)
             if len(units) > 1 else None)
    print(format_table(rows, total))


def _rel(path: Path, base: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def link_base(ld: Path, output: Path, rsp: Path) -> int:
    """Link the compiled objects into the relocatable base ELF for objdiff.

    Three things have to happen that plain `ld -r` does not do:

    * `base.ld` folds armcc's per-symbol `i.NAME` sections back into
      .text/.rodata/.data/.bss so objdiff can pair them with the target.
      `--force-group-allocation` does the same for the COMDAT groups armcc
      puts its `__ARM_common_*` helpers in; older binutils lack the option,
      so the link is retried without it.
    * armcc emits R_ARM_NONE marker relocations (the printf-variant hints, for
      one). objdiff rejects relocation type 0 outright and refuses to read the
      whole file, so they are stripped afterwards.
    * Every named data object is given a section of its own, so objdiff
      credits each one that matches rather than all of `.rodata` or nothing
      (datasplit.py).
    """
    script = Path(__file__).parent / 'base.ld'
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ['-r', '--no-warn-mismatch', '-T', str(script), f'@{rsp}',
            '-o', str(output)]

    result = subprocess.run([str(ld), '--force-group-allocation', *args],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0 and 'force-group-allocation' in result.stderr:
        result = subprocess.run([str(ld), *args], capture_output=True, text=True,
                                check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        # Ninja leaves a failed command's output in place; a half-written base
        # ELF would be read as a real one on the next progress run.
        output.unlink(missing_ok=True)
        return result.returncode

    removed = strip_none_relocs(output)
    if removed:
        print(f"  {output.name}: stripped {removed} R_ARM_NONE relocation(s)")
    split_data_objects(output)
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
        if struct.unpack_from('<I', data, head + 4)[0] != SectionHeaderType.SHT_REL:
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
