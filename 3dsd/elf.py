"""Minimal ELF32 (ARM, little-endian) writing for relocatable objects."""

from enum import IntEnum
from pathlib import Path

from .util import BinaryReader, BinaryWriter, Symbol, pad_to_4


class ELFHeader:
    """The fields of an ELF header the pipeline reads or varies."""
    IDENT = b'\x7fELF\x01\x01\x01' + b'\x00' * 9
    T_M_V = b'\x01\x00\x28\x00\x01\x00\x00\x00'
    EHSIZE = 0x34
    SHENTSIZE = 0x28
    FLAGS = 0x05000000

    def __init__(self, shoff: int, shnum: int, shstrndx: int, valid: bool):
        self.shoff = shoff
        self.shnum = shnum
        self.shstrndx = shstrndx
        self.valid = valid

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ELFHeader":
        """Parse the header; `valid` is False when the ELF magic is absent."""
        reader.seek(0)
        if reader.read_bytes(4) != b'\x7fELF':
            return cls(0, 0, 0, False)
        reader.seek(0x20)
        shoff = reader.read_u32()
        reader.seek(0x30)
        shnum = reader.read_u16()
        shstrndx = reader.read_u16()
        return cls(shoff, shnum, shstrndx, True)

    def write(self, writer: BinaryWriter):
        """Write the header; `shoff`/`shnum` are usually patched afterwards."""
        writer.write_bytes(self.IDENT)
        writer.write_bytes(self.T_M_V)
        writer.write_u32(0)  # e_entry
        writer.write_u32(0)  # e_phoff
        writer.write_u32(self.shoff)
        writer.write_u32(self.FLAGS)
        writer.write_u16(self.EHSIZE)
        writer.write_u16(0)  # e_phentsize
        writer.write_u16(0)  # e_phnum
        writer.write_u16(self.SHENTSIZE)
        writer.write_u16(self.shnum)
        writer.write_u16(self.shstrndx)


class SectionHeaderType(IntEnum):
    """sh_type values the pipeline reads or writes."""
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_GROUP = 17


class SectionHeaderFlags(IntEnum):
    """sh_flags bits the pipeline reads or writes."""
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4


# (sh_type, sh_flags) for each segment name; anything else is read-only data.
_SECTION_FLAGS = {
    '.text': (SectionHeaderType.SHT_PROGBITS,
              SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_EXECINSTR),
    '.rodata': (SectionHeaderType.SHT_PROGBITS, SectionHeaderFlags.SHF_ALLOC),
    '.data': (SectionHeaderType.SHT_PROGBITS,
              SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE),
    '.bss': (SectionHeaderType.SHT_NOBITS,
             SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE),
}
_DEFAULT_SECTION_FLAGS = (SectionHeaderType.SHT_PROGBITS, SectionHeaderFlags.SHF_ALLOC)


class SectionHeaderEntry:  # pylint: disable=too-many-instance-attributes
    """One Elf32_Shdr, field for field."""

    def __init__(self,  # pylint: disable=too-many-arguments,too-many-positional-arguments
                 name_off: int, sh_type: int, flags: int, addr: int, off: int,
                 size: int, link: int = 0, info: int = 0,
                 entsize: int = 0, addralign: int = 0x4):
        self.name_off = name_off
        self.type = sh_type
        self.flags = flags
        self.addr = addr
        self.off = off
        self.size = size
        self.link = link
        self.info = info
        self.entsize = entsize
        self.addralign = addralign

    def write(self, writer: BinaryWriter):
        # Disk order: name, type, flags, addr, offset, size, link, info,
        # addralign, entsize — note addralign comes BEFORE entsize.
        writer.write_u32(self.name_off)
        writer.write_u32(self.type)
        writer.write_u32(self.flags)
        writer.write_u32(self.addr)
        writer.write_u32(self.off)
        writer.write_u32(self.size)
        writer.write_u32(self.link)
        writer.write_u32(self.info)
        writer.write_u32(0 if self.name_off == 0 else self.addralign)
        writer.write_u32(self.entsize)


class SymbolTableEntry:
    """One Elf32_Sym, field for field."""

    def __init__(self, name_off: int, value: int, size: int, info: int, other: int,
                 shndx: int):
        self.name_off = name_off
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name_off)
        writer.write_u32(self.value)
        writer.write_u32(self.size)
        writer.write_u8(self.info)
        writer.write_u8(self.other)
        writer.write_u16(self.shndx)


class ELF:
    """A single-section relocatable object built from original bytes.

    This is what the split writes: one symbol's bytes in a section named
    after its segment, with a mapping symbol (`$a`/`$t`/`$d`) and one global.
    """

    def __init__(self, data: bytes, segment: str, strtab_bytes: bytes,
                 local_syms: list[SymbolTableEntry], global_syms: list[SymbolTableEntry]):
        self.data = data
        self.segment = segment
        self.strtab_bytes = strtab_bytes
        self.local_syms = local_syms
        self.global_syms = global_syms

    @classmethod
    def from_bytes_single(cls, b: bytes, symbol: Symbol) -> "ELF":
        """Wrap original bytes as an object defining the one global `symbol`."""
        local_strtab = bytearray(b'\x00')
        global_strtab = bytearray()
        local_syms = [SymbolTableEntry(len(local_strtab), 0, 0, 0x0, 0x0, 1)]
        local_strtab += symbol.mode.encode('utf-8') + b'\x00'
        thumb = 1 if symbol.mode == '$t' else 0
        global_syms = [SymbolTableEntry(len(global_strtab) + len(local_strtab),
                                        thumb, len(b), 0x12, 0, 1)]
        global_strtab += symbol.name.encode('utf-8') + b'\x00'
        return cls(b, symbol.segment, local_strtab + global_strtab, local_syms, global_syms)

    def write(self, o_file: Path):
        """Write a relocatable ELF holding this one section and its symbols."""
        writer = BinaryWriter()
        ELFHeader(0, 0, 0, True).write(writer)
        text_off = writer.tell()
        writer.write_bytes(self.data)
        pad_to_4(writer)
        symtab_off = writer.tell()
        writer.write_bytes(b'\x00' * 0x10)
        for st in self.local_syms:
            st.write(writer)
        for st in self.global_syms:
            st.write(writer)
        strtab_off = writer.tell()
        writer.write_bytes(self.strtab_bytes)
        shstrtab_off = writer.tell()
        writer.write_u8(0)
        text_name_off = writer.tell() - shstrtab_off
        writer.write_str(self.segment)
        symtab_name_off = writer.tell() - shstrtab_off
        has_syms = bool(self.global_syms or self.local_syms)
        if has_syms:
            writer.write_str('.symtab')
        strtab_name_off = writer.tell() - shstrtab_off
        if has_syms:
            writer.write_str('.strtab')
        shstrtab_name_off = writer.tell() - shstrtab_off
        writer.write_str('.shstrtab')
        pad_to_4(writer)

        sh_off = writer.tell()
        SectionHeaderEntry(0, 0, 0, 0, 0, 0, 0, 0, 0, 0).write(writer)
        sh_type, sh_flags = _SECTION_FLAGS.get(self.segment, _DEFAULT_SECTION_FLAGS)
        SectionHeaderEntry(text_name_off, sh_type, sh_flags, 0, text_off,
                           len(self.data), 0, 0, 0, 1).write(writer)
        if has_syms:
            SectionHeaderEntry(symtab_name_off, SectionHeaderType.SHT_SYMTAB, 0, 0,
                               symtab_off, strtab_off - symtab_off, 3,
                               len(self.local_syms) + 1, 0x10).write(writer)
            SectionHeaderEntry(strtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0,
                               strtab_off, len(self.strtab_bytes), 0, 0, 0).write(writer)
        SectionHeaderEntry(shstrtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0,
                           shstrtab_off, sh_off - shstrtab_off, 0, 0, 0, 0).write(writer)

        writer.seek(0x20)
        writer.write_u32(sh_off)
        writer.seek(0x30)
        writer.write_u16(5 if has_syms else 3)
        writer.write_u16(4 if has_syms else 2)
        writer.flush(o_file)


def _segment_runs(sym_list: list[Symbol], size: int) -> list[tuple[str, int, int]]:
    """Group consecutive symbols of one segment into `(name, start, end)` runs."""
    if not sym_list:
        return [('.text', 0, size)]
    runs = []
    seg_name = sym_list[0].segment
    seg_start = 0
    for sym in sym_list:
        if sym.segment != seg_name:
            runs.append((seg_name, seg_start, sym.addr))
            seg_name = sym.segment
            seg_start = sym.addr
    runs.append((seg_name, seg_start, size))
    return runs


def _target_symtab(sym_list: list[Symbol], runs: list[tuple[str, int, int]],
                   merged: dict[str, list[tuple[int, int]]]):
    """Build `(local_syms, global_syms, strtab)` for `write_target_elf`."""
    sec_names = list(merged)

    # Where each run lands inside its merged section, and which ELF section
    # index that is (shndx 0 is the NULL entry).
    run_offset = {}
    for name, name_runs in merged.items():
        off = 0
        for start, end in name_runs:
            run_offset[(name, start)] = off
            off += end - start
    run_shndx = [sec_names.index(name) + 1 for name, _start, _end in runs]

    local_strtab = bytearray(b'\x00')
    global_strtab = bytearray()
    local_syms = []
    global_syms = []
    run_idx = 0
    for sym in sym_list:
        # Advance to the run containing this symbol
        while run_idx < len(runs) - 1 and sym.addr >= runs[run_idx + 1][1]:
            run_idx += 1
        sec_name, sec_start, _ = runs[run_idx]
        shndx = run_shndx[run_idx]
        sym_value = run_offset[(sec_name, sec_start)] + (sym.addr - sec_start)
        is_code = sec_name == '.text'
        thumb = 1 if is_code and sym.mode == '$t' else 0
        sym_type = 0x12 if is_code else 0x11  # STT_FUNC / STT_OBJECT
        local_syms.append(SymbolTableEntry(len(local_strtab), sym_value, 0, 0x0, 0x0, shndx))
        local_strtab += sym.mode.encode('utf-8') + b'\x00'
        if sym.is_stdlib:
            continue  # library code: leave these bytes unlabelled
        global_syms.append(SymbolTableEntry(len(global_strtab), sym_value | thumb, sym.size,
                                            sym_type, 0, shndx))
        global_strtab += sym.name.encode('utf-8') + b'\x00'
    for g_sym in global_syms:
        g_sym.name_off += len(local_strtab)
    return local_syms, global_syms, bytes(local_strtab + global_strtab)


def write_target_elf(out_path: Path, data: bytes,  # pylint: disable=too-many-locals
                     sym_list: list[Symbol]):
    """Write a relocatable ELF with per-segment sections for objdiff targets.

    Symbols in the `std` namespace are written as bytes but left unnamed: the
    section still carries them, so every following symbol keeps its address,
    while objdiff -- which measures per symbol -- sees nothing there and drops
    the range from total_code, total_functions and total_data alike. The
    `$a`/`$t`/`$d` mapping symbols stay, so the disassembler does not lose
    track of ARM/Thumb state across a discounted region.
    """
    runs = _segment_runs(sym_list, len(data))

    # A segment that stops and starts again produces two runs with one name,
    # and objdiff pairs sections by name: it would keep the first and ignore
    # the rest, silently shrinking the totals. Interleaving is normal once data
    # symbols are in play -- a decompiled table sitting between two
    # undecompiled ones splits .rodata in three -- so the runs are concatenated
    # into one section per name rather than rejected. Addresses are not
    # preserved across the join, which costs nothing: objdiff reads symbol
    # offsets within a section, never their original addresses.
    merged: dict[str, list[tuple[int, int]]] = {}
    for name, start, end in runs:
        merged.setdefault(name, []).append((start, end))
    sec_names = list(merged)

    local_syms, global_syms, strtab_bytes = _target_symtab(sym_list, runs, merged)

    writer = BinaryWriter()
    ELFHeader(0, 0, 0, True).write(writer)

    # Section data: every run of a name, back to back, one section per name.
    sec_offsets = []
    sec_sizes = []
    for name in sec_names:
        sec_offsets.append(writer.tell())
        size = 0
        for start, end in merged[name]:
            writer.write_bytes(data[start:end])
            size += end - start
        sec_sizes.append(size)
        pad_to_4(writer)

    # Symtab
    symtab_off = writer.tell()
    writer.write_bytes(b'\x00' * 0x10)  # NULL symbol
    for st in local_syms:
        st.write(writer)
    for st in global_syms:
        st.write(writer)

    # Strtab
    strtab_off = writer.tell()
    writer.write_bytes(strtab_bytes)

    # Shstrtab
    shstrtab_off = writer.tell()
    writer.write_u8(0)
    sec_name_offsets = []
    for name in sec_names:
        sec_name_offsets.append(writer.tell() - shstrtab_off)
        writer.write_str(name)
    symtab_name_off = writer.tell() - shstrtab_off
    writer.write_str('.symtab')
    strtab_name_off = writer.tell() - shstrtab_off
    writer.write_str('.strtab')
    shstrtab_name_off = writer.tell() - shstrtab_off
    writer.write_str('.shstrtab')
    pad_to_4(writer)

    # Section header table
    sh_off = writer.tell()
    num_sections = len(sec_names)
    # [0] NULL
    SectionHeaderEntry(0, 0, 0, 0, 0, 0, 0, 0, 0, 0).write(writer)
    # [1..N] data sections
    for i, name in enumerate(sec_names):
        sh_type, sh_flags = _SECTION_FLAGS.get(name, _DEFAULT_SECTION_FLAGS)
        SectionHeaderEntry(sec_name_offsets[i], sh_type, sh_flags, 0,
                           sec_offsets[i], sec_sizes[i], 0, 0, 0, 4).write(writer)
    # symtab: link=strtab index, info=first global
    symtab_link = num_sections + 2  # .strtab section index
    SectionHeaderEntry(symtab_name_off, SectionHeaderType.SHT_SYMTAB, 0, 0, symtab_off,
                       strtab_off - symtab_off, symtab_link,
                       len(local_syms) + 1, 0x10).write(writer)
    # strtab
    SectionHeaderEntry(strtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, strtab_off,
                       len(strtab_bytes), 0, 0, 0).write(writer)
    # shstrtab
    SectionHeaderEntry(shstrtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, shstrtab_off,
                       sh_off - shstrtab_off, 0, 0, 0, 0).write(writer)

    # Patch header
    total_sh = num_sections + 4  # NULL + data sections + symtab + strtab + shstrtab
    writer.seek(0x20)
    writer.write_u32(sh_off)
    writer.seek(0x30)
    writer.write_u16(total_sh)
    writer.write_u16(total_sh - 1)  # shstrndx = last section
    writer.flush(out_path)
