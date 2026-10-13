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

Each function's trailing literal pool is split out the same way, as a new
object `<function>$pool` in `.pool:<function>` (see pools.py), so pools are
measured as data on both sides.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from .elf import ELFHeader, SectionHeaderFlags, SectionHeaderType
from .pools import POOL_SEGMENT, pool_section, pool_symbol, trailing_pool
from .util import RelocationType, get_name

#: The base.ld output sections whose objects are given sections of their own.
SPLIT_FROM = ('.rodata', '.data')

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


def split_sections_of(section_names: list[str]) -> dict[str, str]:
    """`{object name: section name}` for every object a base has split out."""
    found = {}
    for sec in section_names:
        parent, sep, name = sec.partition(_SEP)
        if sep and parent in SPLIT_FROM and name:
            found[name] = sec
        elif sep and parent == POOL_SEGMENT and name:
            found[pool_symbol(name)] = sec
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


@dataclass(frozen=True)
class _Object:
    sym_idx: int
    start: int
    end: int
    new_shndx: int
    section: str
    flags: int


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

    pools = _add_pool_symbols(sections, syms, names, symtab.link)
    objects = _choose(sections, syms, names) + pools
    if not objects:
        return 0

    # New data sections first, so their indices are known before the REL ones.
    by_parent: dict[int, list[_Object]] = {}
    first_new = len(sections)
    for k, (shndx, sym_idx, sec_name, flags) in enumerate(objects):
        start = syms[sym_idx][1]
        obj = _Object(sym_idx, start, start + syms[sym_idx][2], first_new + k, sec_name, flags)
        by_parent.setdefault(shndx, []).append(obj)
    for objs in by_parent.values():
        objs.sort(key=lambda o: o.start)

    _repoint_section_relocs(sections, syms, by_parent)

    inner = _inner_relocs(sections, by_parent)

    new_sections = []
    for shndx, objs in by_parent.items():
        parent = sections[shndx]
        for obj in objs:
            align = obj.start & -obj.start or parent.align
            new_sections.append((obj.new_shndx, _Section(
                obj.section, SectionHeaderType.SHT_PROGBITS, obj.flags, 0, 0,
                min(align, max(parent.align, 1)), 0,
                bytearray(parent.data[obj.start:obj.end]))))
            syms[obj.sym_idx][1] = 0
            syms[obj.sym_idx][5] = obj.new_shndx
    new_sections.sort(key=lambda p: p[0])
    sections.extend(sec for _, sec in new_sections)
    for shndx in sorted(inner):
        sections.append(_Section('.rel' + sections[shndx].name, SectionHeaderType.SHT_REL,
                                 _SHF_INFO_LINK, symtab_idx, shndx, 4, 8, inner[shndx]))

    symtab.data = bytearray(b''.join(struct.pack('<IIIBBH', *s) for s in syms))
    _write(path, sections, shstrndx)
    return len(objects)


def _choose(sections: list[_Section], syms: list[list[int]],
            names: list[str]) -> list[tuple[int, int, str, int]]:
    """`(shndx, symbol index, new section, flags)` of every object worth a
    section of its own."""
    counts: dict[str, int] = {}
    for name in names:
        if name:
            counts[name] = counts.get(name, 0) + 1
    chosen = []
    for j, (_, value, size, info, _other, shndx) in enumerate(syms):
        if info & 0xF != _STT_OBJECT or not size or not 0 < shndx < len(sections):
            continue
        sec = sections[shndx]
        if (sec.name in SPLIT_FROM and sec.type == SectionHeaderType.SHT_PROGBITS
                and counts.get(names[j]) == 1 and value + size <= len(sec.data)):
            chosen.append((shndx, j, split_section_name(sec.name, names[j]),
                           sec.flags & ~_SHF_MERGE_STRINGS))
    return chosen


def _add_pool_symbols(sections: list[_Section], syms: list[list[int]], names: list[str],
                      strtab_idx: int) -> list[tuple[int, int, str, int]]:
    """Give each function's trailing literal pool a symbol, and choose it.

    The pool is found as pools.py finds it in the target, so both sides agree
    on its extent. The new symbols are appended as globals, after every
    local, as the symbol table requires.
    """
    counts: dict[str, int] = {}
    for name in names:
        if name:
            counts[name] = counts.get(name, 0) + 1
    by_section: dict[int, list[tuple[int, int, int]]] = {}
    for j, (_, value, size, info, _other, shndx) in enumerate(syms):
        if info & 0xF in (_STT_FUNC, _STT_OBJECT) and size and 0 < shndx < len(sections):
            by_section.setdefault(shndx, []).append((value & ~1, j, value & 1))

    strtab = sections[strtab_idx].data
    chosen = []
    for shndx, entries in by_section.items():
        sec = sections[shndx]
        if not sec.flags & SectionHeaderFlags.SHF_EXECINSTR:
            continue
        entries.sort()
        for k, (start, j, thumb) in enumerate(entries):
            if syms[j][3] & 0xF != _STT_FUNC or counts.get(names[j]) != 1:
                continue
            end = start + syms[j][2]
            limit = entries[k + 1][0] if k + 1 < len(entries) else len(sec.data)
            pool_end = trailing_pool(bytes(sec.data), start, end, bool(thumb), limit)
            if pool_end == end:
                continue
            name = pool_symbol(names[j])
            syms.append([len(strtab), end, pool_end - end, _GLOBAL_OBJECT, 0, shndx])
            names.append(name)
            strtab += name.encode('utf-8') + b'\x00'
            chosen.append((shndx, len(syms) - 1, pool_section(names[j]),
                           int(SectionHeaderFlags.SHF_ALLOC)))
    return chosen


def _inner_relocs(sections: list[_Section],
                  by_parent: dict[int, list[_Object]]) -> dict[int, bytearray]:
    """REL bodies for each new section: the entries inside its object, rebased."""
    inner: dict[int, bytearray] = {}
    for rel in sections:
        if rel.type != SectionHeaderType.SHT_REL or rel.info not in by_parent:
            continue
        for off, info in _rel_entries(rel):
            obj = _find(by_parent[rel.info], off)
            if obj is not None and off + 4 <= obj.end:
                inner.setdefault(obj.new_shndx, bytearray()).extend(
                    struct.pack('<II', off - obj.start, info))
    return inner


def _rel_entries(rel: _Section) -> list[tuple[int, int]]:
    return [struct.unpack_from('<II', rel.data, 8 * k) for k in range(len(rel.data) // 8)]


def _find(objs: list[_Object], off: int) -> _Object | None:
    for obj in objs:
        if obj.start <= off < obj.end:
            return obj
        if obj.start > off:
            break
    return None


def _repoint_section_relocs(sections: list[_Section], syms: list[list[int]],
                            by_parent: dict[int, list[_Object]]):
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
            if sym[3] & 0xF != _STT_SECTION or sym[5] not in by_parent or off + 4 > len(target):
                continue
            reach = sym[1] + struct.unpack_from('<i', target, off)[0]
            obj = _find(by_parent[sym[5]], reach)
            if obj is None:
                continue
            struct.pack_into('<i', target, off, reach - obj.start)
            struct.pack_into('<II', rel.data, 8 * k, off, (obj.sym_idx << 8) | rtype)
