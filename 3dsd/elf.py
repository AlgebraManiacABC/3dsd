from enum import IntEnum
from pathlib import Path

from .util import (
    BinaryReader, BinaryWriter, Symbol, RelocationType,
    RelocationEntry, Bitmask, get_name, pad_to_4,
)


class ELFHeader:
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

    def copy(self) -> "ELFHeader":
        return ELFHeader(self.shoff, self.shnum, self.shstrndx, self.valid)


class SectionHeaderType(IntEnum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_NOBITS = 8
    SHT_REL = 9


class SectionHeaderFlags(IntEnum):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4


class SectionHeaderEntry:
    def __init__(self, name_off: int, type: int, flags: int, addr: int, off: int,
                 size: int, link: int = 0, info: int = 0,
                 entsize: int = 0, addralign: int = 0x4):
        self.name_off = name_off
        self.type = type
        self.flags = flags
        self.addr = addr
        self.off = off
        self.size = size
        self.link = link
        self.info = info
        self.entsize = entsize
        self.addralign = addralign

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SectionHeaderEntry":
        # Disk order: name, type, flags, addr, offset, size, link, info,
        # addralign, entsize — note addralign comes BEFORE entsize.
        name_off, type_, flags, addr, off, size, link, info = (
            reader.read_u32(), reader.read_u32(), reader.read_u32(),
            reader.read_u32(), reader.read_u32(), reader.read_u32(),
            reader.read_u32(), reader.read_u32())
        addralign = reader.read_u32()
        entsize = reader.read_u32()
        return cls(name_off, type_, flags, addr, off, size, link, info,
                   entsize, addralign)

    def write(self, writer: BinaryWriter):
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
    def __init__(self, name_off: int, value: int, size: int, info: int, other: int, shndx: int):
        self.name_off = name_off
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SymbolTableEntry":
        return cls(reader.read_u32(), reader.read_u32(), reader.read_u32(),
                   reader.read_u8(), reader.read_u8(), reader.read_u16())

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name_off)
        writer.write_u32(self.value)
        writer.write_u32(self.size)
        writer.write_u8(self.info)
        writer.write_u8(self.other)
        writer.write_u16(self.shndx)


class ELF:
    def __init__(self, header: ELFHeader, data: bytes, data_off: int, segment: str,
                 mask: Bitmask, imported: list[str], strtab_bytes: bytes,
                 local_syms: list[SymbolTableEntry], global_syms: list[SymbolTableEntry],
                 relocations: list[tuple[RelocationEntry, str]] = None):
        self.header = header
        self.data = data
        self.data_off = data_off
        self.segment = segment
        self.mask = mask
        self.imported_symbols = imported
        self.strtab_bytes = strtab_bytes
        self.local_syms = local_syms
        self.global_syms = global_syms
        self.relocations = relocations or []

    @classmethod
    def from_reader(cls, reader: BinaryReader, section: str = None) -> "ELF | None":
        """Read an object file. If `section` is given, load exactly that PROGBITS
        section and its relocations (returns None when the section is absent)."""
        header = ELFHeader.from_reader(reader)
        if not header.valid:
            if section is not None:
                return None
            return cls(header, b'\x00', 0, '', Bitmask(0), [], b'\x00', [], [])

        sh_entries = []
        text_data = []
        data_off = 0
        text_name_offsets = []
        text_indices = []
        local_syms = []
        global_syms = []
        strtab_index = 0
        rel_indices = []

        for i in range(header.shnum):
            reader.seek(header.shoff + header.SHENTSIZE * i)
            sh_entry = SectionHeaderEntry.from_reader(reader)
            sh_entries.append(sh_entry)
            match sh_entry.type:
                case 1:  # SHT_PROGBITS
                    reader.seek(sh_entry.off)
                    text_data.append(reader.read_bytes(sh_entry.size))
                    text_name_offsets.append(sh_entry.name_off)
                    text_indices.append(i)
                    data_off = sh_entry.addr
                case 2:  # SHT_SYMTAB
                    strtab_index = sh_entry.link
                    reader.seek(sh_entry.off)
                    for j in range(sh_entry.size // 0x10):
                        sym = SymbolTableEntry.from_reader(reader)
                        if j >= sh_entry.info:
                            global_syms.append(sym)
                        else:
                            local_syms.append(sym)
                case 9:  # SHT_REL
                    rel_indices.append(i)

        strings = []
        if strtab_index > 0:
            sh_str = sh_entries[strtab_index]
            reader.seek(sh_str.off)
            strings = reader.read_bytes(sh_str.size)

        sh_shstrtab = sh_entries[header.shstrndx]
        reader.seek(sh_shstrtab.off)
        shstrs = reader.read_bytes(sh_shstrtab.size)
        bin_bytes = None
        sh_type = '.text'
        target_idx = -1
        if section is not None:
            for idx, off in enumerate(text_name_offsets):
                name = get_name(shstrs, off) if off < len(shstrs) else ''
                if name == section:
                    bin_bytes = text_data[idx]
                    target_idx = text_indices[idx]
                    break
            if bin_bytes is None:
                return None
        else:
            for idx, off in enumerate(text_name_offsets):
                name = get_name(shstrs, off) if off < len(shstrs) else ''
                if name in ['.text', '.rodata', '.data', '.bss']:
                    sh_type = name
                    bin_bytes = text_data[idx]
                    target_idx = text_indices[idx]
                    break
            if not bin_bytes and text_data:
                bin_bytes = text_data[0]
                target_idx = text_indices[0]
            if not bin_bytes:
                return cls(header, b'\x00', 0, '', Bitmask(0), [], b'\x00', [], [])

        mask = Bitmask(len(bin_bytes))
        undefined_symbols = []
        relocations = []
        all_syms = local_syms + global_syms
        for i in rel_indices:
            sh_rel = sh_entries[i]
            # sh_info of a REL section is the index of the section it applies to
            if sh_rel.info == target_idx:
                reader.seek(sh_rel.off)
                entsize = sh_rel.entsize if sh_rel.entsize > 0 else 8
                for _ in range(sh_rel.size // entsize):
                    rel_entry = RelocationEntry.from_reader(reader)
                    if rel_entry.symbol_index < len(all_syms):
                        sym = all_syms[rel_entry.symbol_index]
                        rel_name = get_name(strings, sym.name_off) if sym.name_off < len(strings) else ''
                    else:
                        rel_name = f'__unknown_{rel_entry.symbol_index}'
                    undefined_symbols.append(rel_name)
                    mask.add_relocation(rel_entry)
                    relocations.append((rel_entry, rel_name))

        return cls(header, bin_bytes, data_off, sh_type, mask,
                   undefined_symbols, strings, local_syms, global_syms, relocations)

    @classmethod
    def from_path(cls, path: Path) -> "ELF":
        return cls.from_reader(BinaryReader.from_path(path))

    @classmethod
    def from_section(cls, path: Path, sym: str) -> "ELF | None":
        """Load one function's code from an object file.

        armcc --split_sections names an ordinary function's section `i.SYM`
        and a template instantiation's `t.SYM`; a single-function object
        compiled without the option just has `.text`. Returns None if none of
        them is present.
        """
        reader = BinaryReader.from_path(path)
        for name in (f'i.{sym}', f't.{sym}', '.text'):
            elf = cls.from_reader(reader, name)
            if elf is not None:
                return elf
        return None

    @classmethod
    def from_bytes_single(cls, b: bytes, symbol: Symbol) -> "ELF":
        header = ELFHeader(0, 0, 0, True)
        local_strtab = bytearray(b'\x00')
        global_strtab = bytearray()
        local_syms = [SymbolTableEntry(len(local_strtab), 0, 0, 0x0, 0x0, 1)]
        local_strtab += symbol.mode.encode('utf-8') + b'\x00'
        thumb = 1 if symbol.mode == '$t' else 0
        global_syms = [SymbolTableEntry(len(global_strtab) + len(local_strtab),
                                        thumb, len(b), 0x12, 0, 1)]
        global_strtab += symbol.name.encode('utf-8') + b'\x00'
        strtab_bytes = local_strtab + global_strtab
        return cls(header, b, symbol.addr, symbol.segment, Bitmask(len(b)),
                   [], strtab_bytes, local_syms, global_syms)

    @classmethod
    def from_bytes_multi(cls, b: bytes, data_off: int, sym_list: list[Symbol]) -> "ELF":
        header = ELFHeader(0, 0, 0, True)
        mask = Bitmask(len(b))
        local_strtab = bytearray(b'\x00')
        global_strtab = bytearray()
        local_syms = []
        global_syms = []
        segment = sym_list[0].segment if sym_list else '.text'
        for sym in sym_list:
            if sym.addr < data_off or sym.addr >= data_off + len(b):
                continue
            sym_value = sym.addr - data_off
            thumb = 1 if sym.mode == '$t' else 0
            local_syms.append(SymbolTableEntry(len(local_strtab), sym_value, 0, 0x0, 0x0, 1))
            local_strtab += sym.mode.encode('utf-8') + b'\x00'
            global_syms.append(SymbolTableEntry(len(global_strtab), sym_value | thumb, sym.size, 0x12, 0, 1))
            global_strtab += sym.name.encode('utf-8') + b'\x00'
        for g_sym in global_syms:
            g_sym.name_off += len(local_strtab)
        strtab_bytes = local_strtab + global_strtab
        return cls(header, b, data_off, segment, mask, [], strtab_bytes, local_syms, global_syms)

    def write(self, o_file: Path):
        writer = BinaryWriter()
        self.header.write(writer)
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

        match self.segment:
            case '.text':
                sh_type = SectionHeaderType.SHT_PROGBITS
                sh_flags = SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_EXECINSTR
            case '.rodata':
                sh_type = SectionHeaderType.SHT_PROGBITS
                sh_flags = SectionHeaderFlags.SHF_ALLOC
            case '.data':
                sh_type = SectionHeaderType.SHT_PROGBITS
                sh_flags = SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE
            case '.bss':
                sh_type = SectionHeaderType.SHT_NOBITS
                sh_flags = SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE
            case _:
                sh_type = SectionHeaderType.SHT_PROGBITS
                sh_flags = SectionHeaderFlags.SHF_ALLOC

        SectionHeaderEntry(text_name_off, sh_type, sh_flags, 0, text_off,
                           len(self.data), 0, 0, 0, 1).write(writer)
        if has_syms:
            SectionHeaderEntry(symtab_name_off, SectionHeaderType.SHT_SYMTAB, 0, 0, symtab_off,
                               strtab_off - symtab_off, 3, len(self.local_syms) + 1, 0x10).write(writer)
            SectionHeaderEntry(strtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, strtab_off,
                               len(self.strtab_bytes), 0, 0, 0).write(writer)
        SectionHeaderEntry(shstrtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, shstrtab_off,
                           sh_off - shstrtab_off, 0, 0, 0, 0).write(writer)

        writer.seek(0x20)
        writer.write_u32(sh_off)
        writer.seek(0x30)
        writer.write_u16(5 if has_syms else 3)
        writer.write_u16(4 if has_syms else 2)
        writer.flush(o_file)

    def relocations_match(self, other: "ELF", sym_addrs: dict[str, int], other_addr: int) -> bool:
        for rel_entry, sym_name in self.relocations:
            off = rel_entry.off
            rtype = rel_entry.type
            sym_addr = sym_addrs.get(sym_name)
            if sym_addr is None and sym_name.startswith('i.'):
                # armcc --split_sections: reloc against a same-TU function's section
                sym_addr = sym_addrs.get(sym_name[2:])
            if sym_addr is None:
                # Target address unknown (data symbol, library function, or a
                # function only tracked as FUN_xxx): the relocated bytes are
                # masked out of the byte compare, so skip verification here.
                continue
            match rtype:
                case RelocationType.R_ARM_CALL | RelocationType.R_ARM_JUMP24:
                    compiled_instr = int.from_bytes(self.data[off:off + 4], 'little')
                    compiled_imm24 = compiled_instr & 0x00FFFFFF
                    if compiled_imm24 & 0x800000:
                        compiled_imm24 -= 0x1000000
                    A = compiled_imm24 << 2
                    result = (sym_addr + A) - (other_addr + off)
                    expected_imm24 = (result >> 2) & 0x00FFFFFF
                    split_instr = int.from_bytes(other.data[off:off + 4], 'little')
                    if expected_imm24 != (split_instr & 0x00FFFFFF):
                        return False
                case RelocationType.R_ARM_THM_PC22:
                    hw1_c = int.from_bytes(self.data[off:off + 2], 'little')
                    hw2_c = int.from_bytes(self.data[off + 2:off + 4], 'little')
                    s = (hw1_c >> 10) & 1
                    imm10, j1, j2 = hw1_c & 0x3FF, (hw2_c >> 13) & 1, (hw2_c >> 11) & 1
                    imm11 = hw2_c & 0x7FF
                    i1, i2 = ~(j1 ^ s) & 1, ~(j2 ^ s) & 1
                    A = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if s:
                        A -= (1 << 25)
                    expected_target = sym_addr + A + 4

                    hw1_s = int.from_bytes(other.data[off:off + 2], 'little')
                    hw2_s = int.from_bytes(other.data[off + 2:off + 4], 'little')
                    s = (hw1_s >> 10) & 1
                    imm10, j1, j2 = hw1_s & 0x3FF, (hw2_s >> 13) & 1, (hw2_s >> 11) & 1
                    is_blx = ((hw2_s >> 12) & 1) == 0
                    imm11 = hw2_s & 0x7FF
                    i1, i2 = ~(j1 ^ s) & 1, ~(j2 ^ s) & 1
                    offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if s:
                        offset -= (1 << 25)
                    P = other_addr + off
                    actual_target = (((P + 4) & ~3) + offset) if is_blx else ((P + 4) + offset)
                    if expected_target != actual_target:
                        return False
                case RelocationType.R_ARM_ABS32 | RelocationType.R_ARM_TARGET1:
                    A = int.from_bytes(self.data[off:off + 4], 'little')
                    expected_val = (sym_addr + A) & 0xFFFFFFFF
                    actual_val = int.from_bytes(other.data[off:off + 4], 'little')
                    if expected_val != actual_val:
                        return False
        return True

    def __add__(self, other: "ELF"):
        data_size = len(self.data)
        new_mask = self.mask.copy()
        new_mask.extend(other.mask)
        strtab_size = len(self.strtab_bytes)
        new_local = self.local_syms.copy()
        for sym in other.local_syms:
            new_local.append(SymbolTableEntry(sym.name_off + strtab_size, sym.value + data_size,
                                              sym.size, sym.info, sym.other, sym.shndx))
        new_global = self.global_syms.copy()
        for sym in other.global_syms:
            new_global.append(SymbolTableEntry(sym.name_off + strtab_size, sym.value + data_size,
                                               sym.size, sym.info, sym.other, sym.shndx))
        return ELF(self.header.copy(), self.data + other.data, self.data_off, self.segment,
                   new_mask, self.imported_symbols + other.imported_symbols,
                   self.strtab_bytes + other.strtab_bytes, new_local, new_global)

    def __iadd__(self, other):
        data_size = len(self.data)
        self.data += other.data
        self.mask.extend(other.mask)
        strtab_size = len(self.strtab_bytes)
        for sym in other.local_syms:
            self.local_syms.append(SymbolTableEntry(sym.name_off + strtab_size, sym.value + data_size,
                                                    sym.size, sym.info, sym.other, sym.shndx))
        for sym in other.global_syms:
            self.global_syms.append(SymbolTableEntry(sym.name_off + strtab_size, sym.value + data_size,
                                                     sym.size, sym.info, sym.other, sym.shndx))
        self.strtab_bytes += other.strtab_bytes
        self.imported_symbols += other.imported_symbols
        return self

    def __eq__(self, other: "ELF"):
        if len(self.data) != len(other.data):
            return False
        for i in range(len(self.data)):
            m = self.mask.mask[i] & other.mask.mask[i]
            if (self.data[i] & m) != (other.data[i] & m):
                return False
        return True


_SECTION_FLAGS = {
    '.text': (SectionHeaderType.SHT_PROGBITS,
              SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_EXECINSTR),
    '.rodata': (SectionHeaderType.SHT_PROGBITS, SectionHeaderFlags.SHF_ALLOC),
    '.data': (SectionHeaderType.SHT_PROGBITS,
              SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE),
    '.bss': (SectionHeaderType.SHT_NOBITS,
             SectionHeaderFlags.SHF_ALLOC | SectionHeaderFlags.SHF_WRITE),
}


def write_target_elf(out_path: Path, data: bytes, sym_list: list[Symbol]):
    """Write a relocatable ELF with per-segment sections for objdiff targets.

    Symbols in the `std` namespace are written as bytes but left unnamed: the
    section still carries them, so every following symbol keeps its address,
    while objdiff -- which measures per symbol -- sees nothing there and drops
    the range from total_code, total_functions and total_data alike. The
    `$a`/`$t`/`$d` mapping symbols stay, so the disassembler does not lose
    track of ARM/Thumb state across a discounted region.
    """
    # Group symbols into contiguous segment runs
    sections = []  # (name, start, end)
    if not sym_list:
        sections.append(('.text', 0, len(data)))
    else:
        seg_name = sym_list[0].segment
        seg_start = 0
        for sym in sym_list:
            if sym.segment != seg_name:
                sections.append((seg_name, seg_start, sym.addr))
                seg_name = sym.segment
                seg_start = sym.addr
        sections.append((seg_name, seg_start, len(data)))

    # Build section index map: section list index -> ELF shndx (1-based)
    sec_shndx = {}
    for i, (name, _, _) in enumerate(sections):
        sec_shndx[i] = i + 1  # shndx 0 is NULL

    # Build symbol tables
    local_strtab = bytearray(b'\x00')
    global_strtab = bytearray()
    local_syms = []
    global_syms = []
    sec_idx = 0
    for sym in sym_list:
        # Advance to the section containing this symbol
        while sec_idx < len(sections) - 1 and sym.addr >= sections[sec_idx + 1][1]:
            sec_idx += 1
        _, sec_start, _ = sections[sec_idx]
        shndx = sec_shndx[sec_idx]
        sec_name = sections[sec_idx][0]
        sym_value = sym.addr - sec_start
        is_code = sec_name == '.text'
        thumb = 1 if is_code and sym.mode == '$t' else 0
        sym_type = 0x12 if is_code else 0x11  # STT_FUNC / STT_OBJECT
        local_syms.append(SymbolTableEntry(len(local_strtab), sym_value, 0, 0x0, 0x0, shndx))
        local_strtab += sym.mode.encode('utf-8') + b'\x00'
        if sym.is_stdlib:
            continue  # library code: leave these bytes unlabelled
        global_syms.append(SymbolTableEntry(len(global_strtab), sym_value | thumb, sym.size, sym_type, 0, shndx))
        global_strtab += sym.name.encode('utf-8') + b'\x00'
    for g_sym in global_syms:
        g_sym.name_off += len(local_strtab)
    strtab_bytes = bytes(local_strtab + global_strtab)

    # Write the ELF
    writer = BinaryWriter()
    ELFHeader(0, 0, 0, True).write(writer)

    # Section data
    sec_offsets = []
    for name, start, end in sections:
        sec_offsets.append(writer.tell())
        writer.write_bytes(data[start:end])
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
    for name, _, _ in sections:
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
    num_sections = len(sections)
    # [0] NULL
    SectionHeaderEntry(0, 0, 0, 0, 0, 0, 0, 0, 0, 0).write(writer)
    # [1..N] data sections
    for i, (name, start, end) in enumerate(sections):
        sh_type, sh_flags = _SECTION_FLAGS.get(name, (SectionHeaderType.SHT_PROGBITS,
                                                       SectionHeaderFlags.SHF_ALLOC))
        SectionHeaderEntry(sec_name_offsets[i], sh_type, sh_flags, 0,
                           sec_offsets[i], end - start, 0, 0, 0, 4).write(writer)
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
