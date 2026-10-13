"""One section per data object in the objdiff base, so each one scores alone.

objdiff credits matched data per section, and only once that section matches
100% (`report generate` adds a data section's size to `matched_data` or adds
nothing). With every decompiled object in one `.rodata`, a single mismatched
table zeroed the matched data of the whole binary, and the figure stayed at
0% however much was done. objdiff pairs sections by exact name, so giving
each object a section of its own on both sides -- `.rodata:gEnts` in the base
and in the target -- makes matched data count objects that match exactly,
the data counterpart of matched functions. It also keeps every data diff the
size of one object, which matters because that diff is quadratic in length.

The compiler cannot be relied on for this: `--split_sections` gives C data an
`i.NAME` section, but C++ globals share one `.data`. So the base is split
after it is linked, here, and the target follows whatever the base ends up
with (`split_sections_of`), so the two always agree on which objects stand
alone.

Splitting an object out of `.rodata` means three things:

* its bytes are copied into the new section and its symbol moved there;
* the relocations inside it (a vtable's function pointers) are copied to a
  `.rel` section of its own;
* a relocation that reached it through the section symbol -- armcc's way of
  referring to statics, `[.rodata]+0x40` -- is pointed at the object's own
  symbol instead, with its addend (which REL keeps in the relocated bytes)
  rewritten to match. objdiff would have shown it against the object anyway,
  as long as the object sat in `.rodata`.

The original bytes stay where they were, unlabelled. Nothing else in the
section moves, so no other offset needs rewriting.

Each function's trailing literal pool is split out the same way, into
`.pool:<function>`, so that the pool the CSV labels `$d` after a decompiled
function is compared, as data, against the one armcc emitted.
"""

import bisect
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .elf import ELFHeader, SectionHeaderFlags, SectionHeaderType
from .util import RelocationType, get_name

#: The base.ld output sections whose objects are given sections of their own.
SPLIT_FROM = ('.rodata', '.data')

#: Section-name prefix for a function's trailing literal pool.
POOL_SEGMENT = '.pool'

_SEP = ':'
_STT_OBJECT = 1
_STT_FUNC = 2
_STT_SECTION = 3
_GLOBAL_OBJECT = 0x11
_SHF_INFO_LINK = 0x40
#: One object is neither mergeable nor a string table, whatever its parent was.
_SHF_MERGE_STRINGS = 0x30


def split_section_name(segment: str, name: str) -> str:
    """The section a split object lives in, on both sides."""
    return f'{segment}{_SEP}{name}'


def pool_section(function: str) -> str:
    """The section the literal pool after `function` is given, on both sides."""
    return f'{POOL_SEGMENT}{_SEP}{function}'


def split_sections_of(section_names: list[str]) -> dict[str, str]:
    """`{object name: section name}` for every object a base has split out."""
    found = {}
    for sec in section_names:
        parent, sep, name = sec.partition(_SEP)
        if sep and parent in SPLIT_FROM and name:
            found[name] = sec
    return found


@dataclass
class _Section:  # pylint: disable=too-many-instance-attributes
    name: str
    type: int
    flags: int
    link: int
    info: int
    align: int
    entsize: int
    data: bytearray
    nobits_size: int = 0


@dataclass
class _Plan:  # pylint: disable=too-many-instance-attributes
    """One new section: which bytes of its parent go there, and what moves with them.

    `ranges` are copied in order and laid end to end, which is how a function
    loses the pools in its middle: its code ranges make one section, its data
    ranges (and trailing pool) another. `moves` are further symbols -- the
    function's own `$a`/`$t` mapping symbols -- that follow their bytes.
    """
    parent: int
    sym_idx: int
    section: str
    flags: int
    ranges: list[tuple[int, int]]
    moves: list[int] = field(default_factory=list)
    new_shndx: int = 0

    @property
    def start(self) -> int:
        return self.ranges[0][0]

    @property
    def size(self) -> int:
        return sum(end - start for start, end in self.ranges)


class _Index:  # pylint: disable=too-few-public-methods
    """Where each byte of a parent section went: `(plan, offset in its new section)`."""

    def __init__(self, plans: list[_Plan]):
        self.entries = []
        for plan in plans:
            base = 0
            for start, end in plan.ranges:
                self.entries.append((start, end, plan, base))
                base += end - start
        self.entries.sort(key=lambda e: e[0])
        self.starts = [e[0] for e in self.entries]

    def locate(self, off: int) -> tuple[_Plan, int] | None:
        i = bisect.bisect_right(self.starts, off) - 1
        if i >= 0:
            start, end, plan, base = self.entries[i]
            if off < end:
                return plan, base + off - start
        return None


def _read(data: bytes) -> list[_Section] | None:
    if len(data) < ELFHeader.EHSIZE or data[:4] != b'\x7fELF':
        return None
    shoff = struct.unpack_from('<I', data, 0x20)[0]
    shnum, shstrndx = struct.unpack_from('<HH', data, 0x30)
    raw = [struct.unpack_from('<10I', data, shoff + ELFHeader.SHENTSIZE * i)
           for i in range(shnum)]
    if shstrndx >= shnum:
        return None
    shstr = data[raw[shstrndx][4]:raw[shstrndx][4] + raw[shstrndx][5]]
    sections = []
    for s in raw:
        body = b'' if s[1] == SectionHeaderType.SHT_NOBITS else data[s[4]:s[4] + s[5]]
        name = get_name(shstr, s[0]) if s[0] < len(shstr) else ''
        sections.append(_Section(name, s[1], s[2], s[6], s[7], s[8], s[9], bytearray(body),
                                 s[5]))
    return sections


def _write(path: Path, sections: list[_Section], shstrndx: int):
    """Lay the sections out afresh, names and all, and write the file."""
    shstr = bytearray(b'\x00')
    name_offs = []
    for sec in sections:
        name_offs.append(len(shstr) if sec.name else 0)
        if sec.name:
            shstr += sec.name.encode('utf-8') + b'\x00'
    sections[shstrndx].data = shstr

    out = bytearray(ELFHeader.EHSIZE)
    offsets = []
    for i, sec in enumerate(sections):
        if i == 0 or sec.type == SectionHeaderType.SHT_NOBITS:
            offsets.append(0 if i == 0 else len(out))
            continue
        out += b'\x00' * (-len(out) % max(sec.align, 4))
        offsets.append(len(out))
        out += sec.data
    out += b'\x00' * (-len(out) % 4)
    shoff = len(out)
    for i, sec in enumerate(sections):
        size = sec.nobits_size if sec.type == SectionHeaderType.SHT_NOBITS else len(sec.data)
        if i == 0:
            out += b'\x00' * ELFHeader.SHENTSIZE
            continue
        out += struct.pack('<10I', name_offs[i], sec.type, sec.flags, 0, offsets[i], size,
                           sec.link, sec.info, sec.align, sec.entsize)

    header = bytearray()
    header += ELFHeader.IDENT + ELFHeader.T_M_V
    header += struct.pack('<IIIIHHHHHH', 0, 0, shoff, ELFHeader.FLAGS, ELFHeader.EHSIZE,
                          0, 0, ELFHeader.SHENTSIZE, len(sections), shstrndx)
    out[:ELFHeader.EHSIZE] = header
    path.write_bytes(bytes(out))


def split_data_objects(path: Path) -> int:
    """Give every named data object in the base a section of its own, in place.

    Returns how many were split. An object whose name is not unique in the
    base stays where it is: two sections of one name would pair by order,
    which says nothing about which object is which.
    """
    data = path.read_bytes()
    sections = _read(data)
    if not sections:
        return 0
    shstrndx = struct.unpack_from('<H', data, 0x32)[0]
    symtab_idx = next((i for i, s in enumerate(sections)
                       if s.type == SectionHeaderType.SHT_SYMTAB), None)
    if symtab_idx is None:
        return 0
    symtab = sections[symtab_idx]
    strtab = bytes(sections[symtab.link].data)
    syms = [list(struct.unpack_from('<IIIBBH', symtab.data, 0x10 * j))
            for j in range(len(symtab.data) // 0x10)]
    names = [get_name(strtab, s[0]) if s[0] < len(strtab) else '' for s in syms]

    plans = _choose(sections, syms, names)
    plans += _plan_functions(sections, syms, names, symtab.link)
    if not plans:
        return 0

    # New sections first, so their indices are known before the REL ones.
    for k, plan in enumerate(plans):
        plan.new_shndx = len(sections) + k
    index = {shndx: _Index([p for p in plans if p.parent == shndx])
             for shndx in {p.parent for p in plans}}

    _repoint_section_relocs(sections, syms, index)
    inner = _inner_relocs(sections, index)

    for plan in plans:
        parent = sections[plan.parent]
        align = plan.start & -plan.start or parent.align
        body = bytearray()
        for start, end in plan.ranges:
            body += parent.data[start:end]
        sections.append(_Section(plan.section, SectionHeaderType.SHT_PROGBITS, plan.flags, 0, 0,
                                 min(align, max(parent.align, 1)), 0, body))
        for j in [plan.sym_idx, *plan.moves]:
            where = index[plan.parent].locate(syms[j][1] & ~1)
            offset = where[1] if where is not None else 0
            syms[j][1] = offset | (syms[j][1] & 1)
            syms[j][5] = plan.new_shndx
        syms[plan.sym_idx][2] = plan.size
    for shndx in sorted(inner):
        sections.append(_Section('.rel' + sections[shndx].name, SectionHeaderType.SHT_REL,
                                 _SHF_INFO_LINK, symtab_idx, shndx, 4, 8, inner[shndx]))

    symtab.data = bytearray(b''.join(struct.pack('<IIIBBH', *s) for s in syms))
    _write(path, sections, shstrndx)
    return len(plans)


def _name_counts(names: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in names:
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _choose(sections: list[_Section], syms: list[list[int]],
            names: list[str]) -> list[_Plan]:
    """A plan for every data object worth a section of its own."""
    counts = _name_counts(names)
    chosen = []
    for j, (_, value, size, info, _other, shndx) in enumerate(syms):
        if info & 0xF != _STT_OBJECT or not size or not 0 < shndx < len(sections):
            continue
        sec = sections[shndx]
        if (sec.name in SPLIT_FROM and sec.type == SectionHeaderType.SHT_PROGBITS
                and counts.get(names[j]) == 1 and value + size <= len(sec.data)):
            chosen.append(_Plan(shndx, j, split_section_name(sec.name, names[j]),
                                sec.flags & ~_SHF_MERGE_STRINGS, [(value, value + size)]))
    return chosen


def _is_mapping(name: str, kind: str) -> bool:
    """armcc's `$d`, `$a` and `$t`, also in their `$d.realdata` forms."""
    return name == kind or name.startswith(kind + '.')


@dataclass
class _Marks:
    """A code section's mapping symbols and sized symbols, in address order."""
    code: list[tuple[int, int]]   # (value, symbol index) of every $a/$t
    data: list[int]               # value of every $d
    sized: list[tuple[int, int]]  # (start, symbol index) of every sized symbol


def _section_marks(sections: list[_Section], syms: list[list[int]],
                   names: list[str]) -> dict[int, _Marks]:
    marks: dict[int, _Marks] = {}
    for j, (_, value, size, info, _other, shndx) in enumerate(syms):
        if not 0 < shndx < len(sections):
            continue
        entry = marks.setdefault(shndx, _Marks([], [], []))
        if _is_mapping(names[j], '$d'):
            entry.data.append(value)
        elif _is_mapping(names[j], '$a') or _is_mapping(names[j], '$t'):
            entry.code.append((value, j))
        elif size and info & 0xF in (_STT_FUNC, _STT_OBJECT):
            entry.sized.append((value & ~1, j))
    for entry in marks.values():
        entry.code.sort()
        entry.data.sort()
        entry.sized.sort()
    return marks


def _plan_functions(sections: list[_Section], syms: list[list[int]], names: list[str],
                    strtab_idx: int) -> list[_Plan]:
    """Separate each function's literal pools from its code.

    armcc marks where data begins with a `$d` mapping symbol and where code
    resumes with `$a`/`$t`, so every boundary is read off the compiler's own
    output rather than worked out:

    * A pool in the middle of a function runs from a `$d` inside it to the
      next `$a`/`$t`. The function's code ranges go to `.text:<function>`,
      laid end to end, with the function symbol and its code mapping symbols;
      it is then exactly the function's instructions.
    * The pool after a function starts at the first `$d` past its end and
      runs, across any further `$d`, to the next `$a`/`$t`, the next sized
      symbol or the end of the section -- armcc leaves it outside the symbol.
    * Both kinds go to `.pool:<function>`, mid-function ones first, under a
      new symbol `<function>$pool`, appended as a global after every local,
      as the symbol table requires.

    The target builds the same two sections from the CSV's mapping rows and
    `$d` labels (objdiff.py), so the two compare as code and as data.
    """
    counts = _name_counts(names)
    strtab = sections[strtab_idx].data
    plans = []
    for shndx, marks in _section_marks(sections, syms, names).items():
        sec = sections[shndx]
        if not sec.flags & SectionHeaderFlags.SHF_EXECINSTR:
            continue
        code_at = [v for v, _ in marks.code]
        bounds = sorted({*code_at, *(e[0] for e in marks.sized), len(sec.data)})
        for start, j in marks.sized:
            if syms[j][3] & 0xF != _STT_FUNC or counts.get(names[j]) != 1:
                continue
            end = start + syms[j][2]
            inner = _inner_pools(marks, start, end)
            pools = list(inner)
            limit = next(b for b in bounds if b >= end)
            trailing = next((a for a in marks.data if end <= a < limit), None)
            if trailing is not None:
                pools.append((trailing, next(b for b in bounds if b > trailing)))
            if inner and start in code_at:
                code = _complement(start, end, inner)
                moves = [k for v, k in marks.code if any(a <= v < b for a, b in code)]
                plans.append(_Plan(shndx, j, f'.text{_SEP}{names[j]}', sec.flags, code, moves))
            elif inner:
                continue  # no $a/$t to carry the mode over; leave the function whole
            if not pools:
                continue
            syms.append([len(strtab), pools[0][0], 0, _GLOBAL_OBJECT, 0, shndx])
            names.append(names[j] + '$pool')
            strtab += names[-1].encode('utf-8') + b'\x00'
            plans.append(_Plan(shndx, len(syms) - 1, pool_section(names[j]),
                               int(SectionHeaderFlags.SHF_ALLOC), pools))
    return plans


def _inner_pools(marks: _Marks, start: int, end: int) -> list[tuple[int, int]]:
    """`(start, end)` of each data run strictly inside a function."""
    pools = []
    for d in marks.data:
        if not start < d < end or (pools and d < pools[-1][1]):
            continue
        resume = next((v for v, _ in marks.code if v > d), end)
        pools.append((d, min(resume, end)))
    return pools


def _complement(start: int, end: int, holes: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = []
    cur = start
    for a, b in holes:
        if a > cur:
            out.append((cur, a))
        cur = max(cur, b)
    if cur < end:
        out.append((cur, end))
    return out


def _inner_relocs(sections: list[_Section], index: dict[int, _Index]) -> dict[int, bytearray]:
    """REL bodies for each new section: the entries inside its ranges, rebased."""
    inner: dict[int, bytearray] = {}
    for rel in sections:
        if rel.type != SectionHeaderType.SHT_REL or rel.info not in index:
            continue
        for off, info in _rel_entries(rel):
            where = index[rel.info].locate(off)
            if where is not None:
                inner.setdefault(where[0].new_shndx, bytearray()).extend(
                    struct.pack('<II', where[1], info))
    return inner


def _rel_entries(rel: _Section) -> list[tuple[int, int]]:
    return [struct.unpack_from('<II', rel.data, 8 * k) for k in range(len(rel.data) // 8)]


def _repoint_section_relocs(sections: list[_Section], syms: list[list[int]],
                            index: dict[int, _Index]):
    """Point `[.rodata]+N` references into a split object at the object itself.

    Only R_ARM_ABS32 is rewritten: it is how code and data take an object's
    address, and its addend is the whole relocated word.
    """
    for rel in sections:
        if rel.type != SectionHeaderType.SHT_REL or not 0 < rel.info < len(sections):
            continue
        target = sections[rel.info].data
        for k in range(len(rel.data) // 8):
            off, info = struct.unpack_from('<II', rel.data, 8 * k)
            sym_idx, rtype = info >> 8, info & 0xFF
            if rtype != RelocationType.R_ARM_ABS32 or sym_idx >= len(syms):
                continue
            sym = syms[sym_idx]
            if sym[3] & 0xF != _STT_SECTION or sym[5] not in index or off + 4 > len(target):
                continue
            where = index[sym[5]].locate(sym[1] + struct.unpack_from('<i', target, off)[0])
            if where is None:
                continue
            struct.pack_into('<i', target, off, where[1])
            struct.pack_into('<II', rel.data, 8 * k, off, (where[0].sym_idx << 8) | rtype)
