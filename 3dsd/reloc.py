"""Relocations for the objdiff target, recovered with the base as a guide.

objdiff diffs two relocatable objects. The base is one -- `ld -r` over the
compiled sources -- but the target is cut from a linked binary, where every
call and every address load has already been resolved. A `bl helper` in the
base is `ebfffffe` plus an R_ARM_CALL against `helper`; in the target it is a
bare `bl` with a fixed offset. objdiff counts that as a mismatch, and no
setting relaxes it: the instruction bytes differ as well as the relocation.
A function whose compiled code is identical to the original therefore never
reached 100% if it called anything or loaded a global's address.

code.bin has no relocation table, so they are recovered from the code, with
the compiled twin deciding where to look:

* Only symbols that have a twin in the base are touched, and only for the
  relocation types the twin itself uses. Undecompiled code pairs with nothing,
  so relocations there would change nothing.
* Within such a function, every instruction of a relocated class is found by
  a masked search -- `bl`/`blx`/`b` by their opcode bits, literal-pool words
  through the pc-relative `ldr` that loads them -- not only the ones at the
  twin's offsets, so a call still pairs when the code around it has shifted.
* The address each one reaches is looked up in the symbol CSV, and that name
  becomes the relocation's symbol. Branches inside the function are local and
  are left alone.
* The relocated bytes are rewritten to the form the compiler leaves before
  linking (`bl` as `ebfffffe`, a pool word as just its addend). objdiff reads
  the addend from those bytes, so a relocation over resolved bytes still
  mismatches.

armcc does not always name what a relocation points at. String literals, and
code references to static data, go through the section symbol plus an offset
(except at -O0, where most builds name each static). Data initializers always
use the object's own name. objdiff shows such a relocation against whatever
symbol sits at that offset in the base -- often a `$d` mapping symbol, or
`[.rodata]` itself -- which no CSV name can reproduce. So when the twin has
one, the target refers to it by exactly the name and addend objdiff will show
for the base, but only after confirming that both point at the same thing:
the same name at the same offset if the base names it, or else the same bytes.
"""

import bisect
import struct
from dataclasses import dataclass

from .elf import ELFHeader, SectionHeaderType, TargetReloc
from .util import BinaryReader, RelocationType, Symbol, get_name

_STT_SECTION = 3
_SHN_LORESERVE = 0xFF00

_ARM_BRANCHES = (RelocationType.R_ARM_CALL, RelocationType.R_ARM_JUMP24,
                 RelocationType.R_ARM_PC24)
_THUMB_SHORT = (RelocationType.R_ARM_THM_JUMP11, RelocationType.R_ARM_THM_JUMP8)

#: Where a branch's pc reads from, relative to the instruction. The compiler
#: folds the same bias into a branch relocation's addend (`bl` to the symbol
#: itself is `ebfffffe`: an addend of -8).
_PC_BIAS = {
    RelocationType.R_ARM_CALL: 8, RelocationType.R_ARM_JUMP24: 8,
    RelocationType.R_ARM_PC24: 8, RelocationType.R_ARM_THM_PC22: 4,
    RelocationType.R_ARM_THM_JUMP11: 4, RelocationType.R_ARM_THM_JUMP8: 4,
}

#: Strings are the commonest section-relative reference with no CSV entry of
#: their own; one longer than this is not plausibly a single literal.
_MAX_STRING = 4096


def _sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def implicit_addend(rtype: int, b: bytes) -> int:
    """The addend a REL relocation carries in its bytes, decoded as objdiff does."""
    if rtype in _ARM_BRANCHES:
        return _sext((struct.unpack_from('<I', b)[0] & 0xFFFFFF) << 2, 26)
    if rtype == RelocationType.R_ARM_THM_PC22:
        hi, lo = struct.unpack_from('<HH', b)
        return _sext((((hi & 0x7FF) << 11) | (lo & 0x7FF)) << 1, 23)
    if rtype == RelocationType.R_ARM_THM_JUMP11:
        return _sext((struct.unpack_from('<H', b)[0] & 0x7FF) << 1, 12)
    if rtype == RelocationType.R_ARM_THM_JUMP8:
        return _sext((struct.unpack_from('<H', b)[0] & 0xFF) << 1, 9)
    return struct.unpack_from('<i', b)[0]


def encode(rtype: int, original: bytes, addend: int) -> bytes:
    """`original` rewritten to carry `addend`, as the compiler leaves it.

    A call is always written as `bl`: armcc emits `bl` with R_ARM_CALL even to
    a Thumb function, and the linker turns it into `blx`. Leaving the linked
    `blx` would mismatch the opcode as well.
    """
    if rtype in _ARM_BRANCHES:
        top = struct.unpack_from('<I', original)[0] & 0xFF000000
        if rtype == RelocationType.R_ARM_CALL or top >> 28 == 0xF:
            top = 0xEB000000
        return struct.pack('<I', top | ((addend >> 2) & 0xFFFFFF))
    if rtype == RelocationType.R_ARM_THM_PC22:
        imm = (addend >> 1) & 0x3FFFFF
        return struct.pack('<HH', 0xF000 | (imm >> 11), 0xF800 | (imm & 0x7FF))
    if rtype == RelocationType.R_ARM_THM_JUMP11:
        half = struct.unpack_from('<H', original)[0]
        return struct.pack('<H', (half & 0xF800) | ((addend >> 1) & 0x7FF))
    if rtype == RelocationType.R_ARM_THM_JUMP8:
        half = struct.unpack_from('<H', original)[0]
        return struct.pack('<H', (half & 0xFF00) | ((addend >> 1) & 0xFF))
    return struct.pack('<I', addend & 0xFFFFFFFF)


# --- The base object --------------------------------------------------------

@dataclass(frozen=True)
class BaseSymbol:
    """One entry of the base's symbol table."""
    name: str
    value: int
    size: int
    kind: int
    shndx: int


@dataclass(frozen=True)
class BaseReloc:
    """One base relocation, with its implicit addend already decoded."""
    offset: int
    rtype: int
    sym: BaseSymbol
    addend: int

    def reach(self) -> int:
        """Section offset this relocation refers to, branch bias included."""
        return self.sym.value + self.addend + _PC_BIAS.get(self.rtype, 0)


class BaseObject:
    """The parts of the relocatable base ELF that relocation recovery reads."""

    def __init__(self, names: list[str], contents: list[bytes | None],
                 symbols: list[BaseSymbol], relocs: dict[int, list[BaseReloc]]):
        self.names = names
        self._index = {name: i for i, name in enumerate(names)}
        self.contents = contents
        self.relocs = relocs
        self.by_name: dict[str, list[BaseSymbol]] = {}
        # Named symbols per section in address order, for "what is at offset X".
        self._named: dict[int, list[BaseSymbol]] = {}
        # Every symbol per section, ordered the way objdiff orders them.
        self._ordered: dict[int, list[BaseSymbol]] = {}
        for sym in symbols:
            if sym.kind == _STT_SECTION or not 0 < sym.shndx < len(names):
                continue
            self._ordered.setdefault(sym.shndx, []).append(sym)
            if not sym.name:
                continue
            self.by_name.setdefault(sym.name, []).append(sym)
            if sym.size:
                self._named.setdefault(sym.shndx, []).append(sym)
        for entries in self._named.values():
            entries.sort(key=lambda s: s.value & ~1)
        for entries in self._ordered.values():
            entries.sort(key=lambda s: (s.value, s.size))

    def twin(self, name: str, section: str) -> BaseSymbol | None:
        """The base's definition of `name` in a section called `section`."""
        for sym in self.by_name.get(name, []):
            if self.names[sym.shndx] == section and sym.size:
                return sym
        # A section holding a single split object (`.pool:<function>`) pairs
        # whole, whatever each side calls the object in it.
        shndx = self._index.get(section) if ':' in section else None
        inside = self._named.get(shndx, []) if shndx is not None else []
        if len(inside) == 1:
            return inside[0]
        return None

    def relocs_in(self, sym: BaseSymbol) -> dict[int, BaseReloc]:
        """The relocations inside `sym`, keyed by offset from its start."""
        start = sym.value & ~1
        rels = self.relocs.get(sym.shndx, [])
        lo = bisect.bisect_left(rels, start, key=lambda r: r.offset)
        out = {}
        for rel in rels[lo:]:
            if rel.offset >= start + sym.size:
                break
            out[rel.offset - start] = rel
        return out

    def named_at(self, shndx: int, offset: int) -> tuple[BaseSymbol, int] | None:
        """The named symbol covering `offset` in a section, and the offset into it."""
        entries = self._named.get(shndx, [])
        i = bisect.bisect_right(entries, offset, key=lambda s: s.value & ~1) - 1
        if i >= 0:
            sym = entries[i]
            start = sym.value & ~1
            if start <= offset < start + sym.size:
                return sym, offset - start
        return None

    def objdiff_view(self, rel: BaseReloc) -> tuple[str, int]:
        """The `(symbol name, addend)` objdiff will show for a base relocation.

        objdiff does not keep a section-relative relocation as it is: it
        retargets it to the best symbol at that address (`best_symbol` in
        objdiff-core's obj/read.rs) -- the first one, in address-then-size
        order, at the closest address at or below it that is not a sized
        symbol ending before it. A mapping symbol (`$d`) qualifies. Only when
        none does is the section symbol kept, shown as `[.rodata]`.
        """
        if rel.sym.kind != _STT_SECTION:
            return rel.sym.name, rel.addend
        target = rel.sym.value + rel.addend
        entries = self._ordered.get(rel.sym.shndx, [])
        i = bisect.bisect_right(entries, target, key=lambda s: s.value) - 1
        if i >= 0:
            closest = entries[i].value
            while i > 0 and entries[i - 1].value == closest:
                i -= 1
            for sym in entries[i:]:
                if sym.value > target:
                    break
                if sym.size and sym.value + sym.size <= target:
                    continue
                return sym.name, target - sym.value
        return f'[{self.names[rel.sym.shndx]}]', rel.addend

    def has_inner_data(self, sym: BaseSymbol) -> bool:
        """Whether armcc marked data (`$d`) inside a function's extent."""
        start = sym.value & ~1
        return any(s.name == '$d' and start < s.value < start + sym.size
                   for s in self._ordered.get(sym.shndx, []))

    def bytes_at(self, sym: BaseSymbol, offset: int, size: int) -> bytes | None:
        content = self.contents[sym.shndx]
        start = (sym.value & ~1) + offset
        if content is None or start + size > len(content):
            return None
        return content[start:start + size]


def read_base(data: bytes) -> BaseObject | None:
    """Parse a relocatable ELF's sections, symbols and REL relocations."""
    reader = BinaryReader('base', data)
    header = ELFHeader.from_reader(reader)
    if not header.valid or header.shstrndx >= header.shnum:
        return None

    raw = []
    for i in range(header.shnum):
        reader.seek(header.shoff + header.SHENTSIZE * i)
        raw.append(struct.unpack('<10I', reader.read_bytes(header.SHENTSIZE)))
    shstr = data[raw[header.shstrndx][4]:][:raw[header.shstrndx][5]]
    names = [get_name(shstr, s[0]) if s[0] < len(shstr) else '' for s in raw]
    contents = [data[s[4]:s[4] + s[5]] if s[1] != SectionHeaderType.SHT_NOBITS else None
                for s in raw]

    symtab_idx = next((i for i, s in enumerate(raw) if s[1] == SectionHeaderType.SHT_SYMTAB),
                      None)
    if symtab_idx is None:
        return None
    symbols = _read_symbols(contents[symtab_idx] or b'', contents[raw[symtab_idx][6]] or b'')
    relocs = _read_relocs(data, raw, contents, symbols)
    return BaseObject(names, contents, symbols, relocs)


def _read_symbols(symtab: bytes, strtab: bytes) -> list[BaseSymbol]:
    symbols = []
    for j in range(len(symtab) // 0x10):
        name_off, value, size, info, _other, shndx = struct.unpack_from('<IIIBBH', symtab,
                                                                        0x10 * j)
        name = get_name(strtab, name_off) if name_off < len(strtab) else ''
        if shndx >= _SHN_LORESERVE:
            shndx = 0
        symbols.append(BaseSymbol(name, value, size, info & 0xF, shndx))
    return symbols


def _read_relocs(data: bytes, raw: list[tuple], contents: list[bytes | None],
                 symbols: list[BaseSymbol]) -> dict[int, list[BaseReloc]]:
    """Every REL entry, grouped by the section it applies to, in offset order."""
    relocs: dict[int, list[BaseReloc]] = {}
    for sec in raw:
        target = sec[7]
        if sec[1] != SectionHeaderType.SHT_REL or not 0 < target < len(raw):
            continue
        body = data[sec[4]:sec[4] + sec[5]]
        content = contents[target] or b''
        for k in range(len(body) // 8):
            offset, info = struct.unpack_from('<II', body, 8 * k)
            sym_idx, rtype = info >> 8, info & 0xFF
            size = 2 if rtype in _THUMB_SHORT else 4
            if not rtype or sym_idx >= len(symbols) or offset + size > len(content):
                continue
            addend = implicit_addend(rtype, content[offset:offset + size])
            relocs.setdefault(target, []).append(
                BaseReloc(offset, rtype, symbols[sym_idx], addend))
    for rels in relocs.values():
        rels.sort(key=lambda r: r.offset)
    return relocs


# --- The target: a masked search over one function --------------------------

@dataclass(frozen=True)
class _Candidate:
    """A place in the target that may need a relocation."""
    off: int     # binary offset of the bytes
    size: int    # 2 or 4
    rtype: int   # the type its instruction class implies
    reach: int   # binary offset it refers to (for ABS32: the raw value - base)


def _arm_pools(data: bytes, start: int, end: int) -> set[int]:
    """Literal-pool words loaded by `ldr rX, [pc, #±imm]` in an ARM function."""
    pools = set()
    for off in range(start, end - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        if word & 0x0F7F0000 == 0x051F0000 and word >> 28 != 0xF:
            imm = word & 0xFFF
            addr = off + 8 + (imm if word & 0x00800000 else -imm)
            if start <= addr <= end - 4 and addr % 4 == 0:
                pools.add(addr)
    return pools


def _thumb_pools(data: bytes, start: int, end: int) -> set[int]:
    """Literal-pool words loaded by `ldr rX, [pc, #imm]` in a Thumb function."""
    pools = set()
    for off in range(start, end - 1, 2):
        half = struct.unpack_from('<H', data, off)[0]
        if half & 0xF800 == 0x4800:
            addr = ((off + 4) & ~3) + (half & 0xFF) * 4
            if start <= addr <= end - 4:
                pools.add(addr)
    return pools


def _pick(options: tuple[int, ...], types: set[int]) -> int | None:
    return next((t for t in options if t in types), None)


def _scan_arm(data: bytes, start: int, end: int, types: set[int],
              base_addr: int, pools: set[int]) -> list[_Candidate]:
    out = []
    for off in range(start, end - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        if off in pools:
            if RelocationType.R_ARM_ABS32 in types:
                out.append(_Candidate(off, 4, RelocationType.R_ARM_ABS32, word - base_addr))
            continue
        if word & 0x0E000000 != 0x0A000000:
            continue
        cond = word >> 28
        reach = off + 8 + _sext((word & 0xFFFFFF) << 2, 26)
        if cond == 0xF:  # blx: always a call, to Thumb, H selects the halfword
            reach += (word >> 23) & 2
            rtype = _pick((RelocationType.R_ARM_CALL, RelocationType.R_ARM_PC24), types)
        elif word & 0x01000000 and cond == 0xE:
            rtype = _pick((RelocationType.R_ARM_CALL, RelocationType.R_ARM_PC24), types)
        else:  # b, or a conditional bl
            rtype = _pick((RelocationType.R_ARM_JUMP24, RelocationType.R_ARM_PC24), types)
        if rtype is not None and not start <= reach < end:
            out.append(_Candidate(off, 4, rtype, reach))
    return out


def _scan_thumb(data: bytes, start: int, end: int, types: set[int],
                base_addr: int, pools: set[int]) -> list[_Candidate]:
    out = []
    off = start
    while off < end - 1:
        if off in pools:
            if RelocationType.R_ARM_ABS32 in types:
                value = struct.unpack_from('<I', data, off)[0]
                out.append(_Candidate(off, 4, RelocationType.R_ARM_ABS32, value - base_addr))
            off += 4
            continue
        half = struct.unpack_from('<H', data, off)[0]
        if half & 0xF800 == 0xF000 and off + 4 <= end:
            low = struct.unpack_from('<H', data, off + 2)[0]
            if low & 0xF800 in (0xF800, 0xE800):
                disp = _sext(((half & 0x7FF) << 12) | ((low & 0x7FF) << 1), 23)
                pc = off + 4 if low & 0x1000 else (off + 4) & ~3
                if (RelocationType.R_ARM_THM_PC22 in types
                        and not start <= pc + disp < end):
                    out.append(_Candidate(off, 4, RelocationType.R_ARM_THM_PC22, pc + disp))
                off += 4
                continue
        if half & 0xF800 == 0xE000:
            reach = off + 4 + _sext((half & 0x7FF) << 1, 12)
            if RelocationType.R_ARM_THM_JUMP11 in types and not start <= reach < end:
                out.append(_Candidate(off, 2, RelocationType.R_ARM_THM_JUMP11, reach))
        elif half & 0xF000 == 0xD000 and (half >> 8) & 0xF < 0xE:
            reach = off + 4 + _sext((half & 0xFF) << 1, 9)
            if RelocationType.R_ARM_THM_JUMP8 in types and not start <= reach < end:
                out.append(_Candidate(off, 2, RelocationType.R_ARM_THM_JUMP8, reach))
        off += 2
    return out


def _same_class(a: int, b: int) -> bool:
    """Whether two relocation types fit the same instruction."""
    if a in _ARM_BRANCHES and b in _ARM_BRANCHES:
        return True
    return a == b


# --- Recovery ---------------------------------------------------------------

class _CsvIndex:
    """The symbol CSV, searchable by the address a reference reaches."""

    def __init__(self, symbols: list[Symbol]):
        self.syms = sorted(symbols, key=lambda s: s.addr)
        self.addrs = [s.addr for s in self.syms]

    def containing(self, off: int) -> Symbol | None:
        """The symbol whose extent covers `off`; a sized one wins over a label."""
        i = bisect.bisect_right(self.addrs, off) - 1
        if i < 0:
            return None
        addr = self.addrs[i]
        best = None
        while i >= 0 and self.addrs[i] == addr:
            sym = self.syms[i]
            if off < sym.addr + max(sym.size, 1) and (best is None or sym.size > best.size):
                best = sym
            i -= 1
        return best


class RelocRecovery:  # pylint: disable=too-few-public-methods
    """Recovers one binary's target relocations against its base ELF."""

    def __init__(self, data: bytes, csv: list[Symbol], base: BaseObject,
                 base_addr: int, pointers: bool = True):
        """`pointers` is False where words in the binary are not addresses at
        all, so no R_ARM_ABS32 is recovered. Where they are, a value only
        counts as an address if it lands inside a CSV symbol -- code, data or
        .bss -- which is also what keeps ordinary constants out."""
        self.orig = bytes(data)  # what is read: scans see the binary as linked
        self.data = bytearray(data)  # what is written: the patched copy
        self.csv = _CsvIndex(csv)
        self.base = base
        self.base_addr = base_addr
        self.pointers = pointers
        self.relocs: list[TargetReloc] = []
        self.unresolved = 0
        self.mapping: list[tuple[int, str]] = []
        #: Functions whose data the CSV marks itself; no pools are inferred there.
        self.marked: set[str] = set()

    def run(self, syms: list[Symbol]) -> tuple[bytes, list[TargetReloc]]:
        """Recover relocations for every target symbol with a twin in the base.

        Also collects `mapping`: `$d` over each literal pool found on the way
        and the function's own `$a`/`$t` after it. The CSV gives one mapping
        symbol per function, so without these a pool decodes as instructions,
        and in Thumb a relocated pool word then straddles two of them.
        """
        # A split section ('.pool:Func', '.rodata:gTable') is one object in the
        # base but may be several labels in the target -- a pool the CSV marks
        # word by word -- so it is handled whole, from its first byte.
        split: dict[str, list[Symbol]] = {}
        for sym in syms:
            if sym.is_stdlib or sym.name.startswith('pad_'):
                continue
            if ':' in sym.segment:
                split.setdefault(sym.segment, []).append(sym)
                continue
            twin = self.base.twin(sym.name, sym.segment)
            if twin is None:
                continue
            if sym.segment == '.text':
                self._function(sym, twin)
            else:
                self._data(sym, twin)
        for segment, parts in split.items():
            twin = self.base.twin(parts[0].name, segment)
            if twin is not None:
                start = min(p.addr for p in parts)
                end = max(p.addr + p.size for p in parts)
                self._data(Symbol(start, parts[0].name, '$d', end - start, segment), twin)
        return bytes(self.data), self.relocs

    def _function(self, sym: Symbol, twin: BaseSymbol):
        start, end = sym.addr, sym.addr + sym.size
        thumb = sym.mode == '$t'
        pools = (_thumb_pools if thumb else _arm_pools)(self.orig, start, end)
        if sym.name not in self.marked:
            self._map_pools(pools, end, sym.mode)
        twin_relocs = self.base.relocs_in(twin)
        types = {r.rtype for r in twin_relocs.values()}
        if not types:
            return
        scan = _scan_thumb if thumb else _scan_arm
        cands = scan(self.orig, start, end, types, self.base_addr, pools)

        # Constants the twin keeps as plain words: a target pool word with one
        # of these values is that constant, not an address.
        plain = set()
        if twin.size >= 4:
            body = self.base.bytes_at(twin, 0, twin.size - twin.size % 4) or b''
            plain = {struct.unpack_from('<I', body, k)[0] for k in range(0, len(body), 4)
                     if k not in twin_relocs}

        unused = dict(twin_relocs)
        for cand in cands:
            rel = cand.off - start
            partner = twin_relocs.get(rel)
            if partner is not None and not _same_class(partner.rtype, cand.rtype):
                partner = None
            if partner is None:
                # Identical bytes with no relocation in the twin: already a match.
                if self.base.bytes_at(twin, rel, cand.size) == self.orig[cand.off:cand.off
                                                                         + cand.size]:
                    continue
                if (cand.rtype == RelocationType.R_ARM_ABS32
                        and cand.reach + self.base_addr in plain):
                    continue
            self._emit(cand, partner, unused)

    def _map_pools(self, pools: set[int], end: int, mode: str):
        for addr in sorted(pools):
            if addr - 4 not in pools:
                self.mapping.append((addr, '$d'))
            if addr + 4 not in pools and addr + 4 < end:
                self.mapping.append((addr + 4, mode))

    def _data(self, sym: Symbol, twin: BaseSymbol):
        """Pointers in a decompiled data object, at the offsets the twin has them."""
        for rel, partner in self.base.relocs_in(twin).items():
            if partner.rtype != RelocationType.R_ARM_ABS32 or rel + 4 > sym.size:
                continue
            off = sym.addr + rel
            value = struct.unpack_from('<I', self.orig, off)[0]
            self._emit(_Candidate(off, 4, partner.rtype, value - self.base_addr),
                       partner, {rel: partner})

    def _emit(self, cand: _Candidate, partner: BaseReloc | None,
              unused: dict[int, BaseReloc]):
        rtype = partner.rtype if partner is not None else cand.rtype
        reach = cand.reach
        if rtype == RelocationType.R_ARM_ABS32 and not self.pointers:
            return

        # A section-relative reference in the twin: once both are confirmed to
        # point at the same thing, refer to it the way objdiff names the base's.
        options = [partner] if partner is not None else []
        options += [r for r in unused.values() if r is not partner]
        for opt in options:
            if (opt.sym.kind == _STT_SECTION and _same_class(opt.rtype, rtype)
                    and self._same_referent(opt, reach)):
                for key in [k for k, v in unused.items() if v is opt]:
                    del unused[key]
                name, addend = self.base.objdiff_view(opt)
                self._add(cand, opt.rtype, name, addend)
                return

        if rtype != RelocationType.R_ARM_ABS32:
            reach = self._through_veneer(reach)
        target = self._resolve(reach, rtype)
        if target is None:
            self.unresolved += 1
            return
        sym, addend = target
        self._add(cand, rtype, sym.name, addend)

    def _through_veneer(self, reach: int) -> int:
        """Where a branch really goes, if it lands on a linker veneer.

        The base calls the function itself; the linker may have routed the
        call through a veneer (ARM to Thumb, or out of range), whose own CSV
        name the base never uses. The two shapes armlink emits are followed:
        `ldr pc, [pc, #-4]` with the address after it, and Thumb `bx pc` into
        an ARM `b`.
        """
        for _ in range(2):
            if not 0 <= reach <= len(self.orig) - 8:
                break
            word = struct.unpack_from('<I', self.orig, reach)[0]
            if word == 0xE51FF004:
                reach = struct.unpack_from('<I', self.orig, reach + 4)[0] - self.base_addr
                reach &= ~1
            elif word == 0x46C04778:  # bx pc; nop
                arm = struct.unpack_from('<I', self.orig, reach + 4)[0]
                if arm & 0xFF000000 != 0xEA000000:
                    break
                reach = reach + 4 + 8 + _sext((arm & 0xFFFFFF) << 2, 26)
            else:
                break
        return reach

    def _resolve(self, reach: int, rtype: int) -> tuple[Symbol, int] | None:
        """The CSV symbol a reference reaches, and the addend that reaches it."""
        if rtype == RelocationType.R_ARM_ABS32:
            if reach & 1:
                sym = self.csv.containing(reach - 1)
                if sym is not None and sym.mode == '$t' and sym.segment == '.text':
                    return sym, reach - (sym.addr | 1)
            sym = self.csv.containing(reach)
            return (sym, reach - sym.addr) if sym is not None else None
        sym = self.csv.containing(reach)
        if sym is None:
            return None
        return sym, reach - sym.addr - _PC_BIAS[rtype]

    def _same_referent(self, rel: BaseReloc, reach: int) -> bool:
        """Whether a section-relative base reference and the target agree."""
        base_off = rel.reach()
        if rel.rtype == RelocationType.R_ARM_ABS32 and self._is_thumb_code(reach):
            reach -= 1
            base_off &= ~1
        csv_sym = self.csv.containing(reach)
        named = self.base.named_at(rel.sym.shndx, base_off)
        if named is not None:
            # The base names it after all: then it has to be the same name.
            sym, inner = named
            return csv_sym is not None and csv_sym.name == sym.name \
                and reach - csv_sym.addr == inner
        content = self.base.contents[rel.sym.shndx]
        if content is None or not 0 <= base_off < len(content) or reach >= len(self.orig):
            return False
        if csv_sym is not None and not csv_sym.name.startswith('pad_'):
            size = csv_sym.addr + csv_sym.size - reach
            return size > 0 and self._bytes_agree(rel.sym.shndx, base_off, reach, size)
        # Unnamed bytes on both sides: a string literal, compared through its NUL.
        nul = content.find(b'\x00', base_off, base_off + _MAX_STRING)
        if nul <= base_off:
            return False
        return self._bytes_agree(rel.sym.shndx, base_off, reach, nul + 1 - base_off)

    def _bytes_agree(self, shndx: int, base_off: int, reach: int, size: int) -> bool:
        """Whether base bytes and the original's match, pointers aside.

        A word the base relocates holds an addend where the original holds an
        address, so those words are left out of the comparison.
        """
        ours = bytearray(self.base.contents[shndx][base_off:base_off + size])
        theirs = bytearray(self.orig[reach:reach + size])
        if len(ours) != size or len(theirs) != size:
            return False
        rels = self.base.relocs.get(shndx, [])
        i = bisect.bisect_left(rels, base_off - 3, key=lambda r: r.offset)
        while i < len(rels) and rels[i].offset < base_off + size:
            lo = max(rels[i].offset - base_off, 0)
            hi = min(rels[i].offset + 4 - base_off, size)
            ours[lo:hi] = theirs[lo:hi]
            i += 1
        return ours == theirs

    def _is_thumb_code(self, reach: int) -> bool:
        if not reach & 1:
            return False
        sym = self.csv.containing(reach - 1)
        return sym is not None and sym.mode == '$t' and sym.segment == '.text'

    def _add(self, cand: _Candidate, rtype: int, symbol: str, addend: int):
        original = bytes(self.data[cand.off:cand.off + cand.size])
        self.data[cand.off:cand.off + cand.size] = encode(rtype, original, addend)
        self.relocs.append(TargetReloc(cand.off, int(rtype), symbol))
