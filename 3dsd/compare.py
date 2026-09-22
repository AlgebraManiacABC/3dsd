import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .elf import ELF
from .util import BinaryReader, get_name


def compile_source(source: Path, output: Path, cc: Path, flags: list[str],
                   cwd: Path | None = None):
    """Compile a translation unit. Writes an empty file on failure so the
    build can continue (comparison then falls back to the split object).

    `cwd` must be the project working directory whenever the flags contain
    project-relative paths (`-Iinclude`): ninja runs the compile rule from
    there, and section discovery has to use the same directory or the
    include search fails."""
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(cc)] + flags + ['-c', str(source), '-o', str(output)]
    result = subprocess.run(cmd, cwd=cwd, env=_cc_env(cc))
    if result.returncode != 0:
        output.write_bytes(b'')


def _cc_env(cc: Path) -> dict:
    """The compiler's own directory, prepended to PATH.

    armcc does not assemble `__asm` function bodies itself -- it shells out to
    armasm, which it looks up on PATH. armasm ships alongside armcc, so without
    this any source using embedded assembler fails with a bare
    "'armasm' is not recognized as an internal or external command".
    """
    env = dict(os.environ)
    bin_dir = str(cc.resolve().parent)
    env['PATH'] = bin_dir + os.pathsep + env.get('PATH', '')
    return env


def extract_and_compare(compiled: Path, split: Path, output: Path, sym: str,
                        symbols_csv: Path | None, base_addr: int,
                        split_addr: int, compare_split: Path | None = None) -> bool:
    """Compare one function from a compiled TU against its original bytes.

    The output object always gets the split (original) bytes so the final
    link stays byte-perfect. The comparison result is reported separately by
    objdiff, which diffs the target and base ELFs; nothing here records it.

    `compare_split` overrides what the comparison reads, without affecting
    what is linked. It carries the symbol's bytes extended over the trailing
    padding and literal pool that armcc keeps inside the function's own
    section but which the symbol's declared size does not cover.
    """
    output.parent.mkdir(parents=True, exist_ok=True)

    matched = False
    if compiled.exists() and compiled.stat().st_size > 0:
        compiled_elf = ELF.from_section(compiled, sym)
        if compiled_elf is not None:
            reference = compare_split if compare_split and compare_split.exists() else split
            split_elf = ELF.from_path(reference)
            matched = _matches(compiled_elf, split_elf, sym,
                               symbols_csv, base_addr, split_addr)

    shutil.copy2(split, output)
    return matched


def _matches(compiled: ELF, split: ELF, sym: str, symbols_csv: Path | None,
             base_addr: int, split_addr: int) -> bool:
    if compiled != split:
        return False
    if compiled.relocations:
        if not symbols_csv:
            return False
        sym_addrs = _load_sym_addrs(symbols_csv, base_addr)
        try:
            return compiled.relocations_match(split, sym_addrs, split_addr)
        except Exception as e:
            print(f"  Relocation check error for {sym}: {e}")
            return False
    return True


@dataclass(frozen=True)
class SymbolInfo:
    """One symbol a compiled object defines.

    `segment` is where base.ld routes it, `size` is the length the compiler
    declared, and `extent` is how far it reaches before the next symbol in the
    same section -- longer than `size` whenever a literal pool or alignment
    padding follows, which is what the comparison window has to cover.
    """
    segment: str
    size: int
    extent: int


def discover_symbols(obj_path: Path) -> dict[str, SymbolInfo]:
    """Read an ELF .o and return every symbol it defines, keyed by name.

    This walks `.symtab` rather than the section headers, which matters more
    than it sounds. armcc --split_sections gives each function its own `i.NAME`
    section (`t.NAME` for a template instantiation) and does the same for data
    in C -- but not in C++, where every global in a translation unit lands in
    one shared `.data`. Reading section names therefore finds C data, misses
    C++ data entirely, and finds nothing whatsoever in an object compiled
    without the option.

    The symbol table has no such gap: `gMycLife` is a 16-byte OBJECT in `.data`
    either way, and a function keeps its name and size whether it sits alone in
    `i.NAME` or at some offset inside a shared `.text`. Discovery is then
    independent of --split_sections, which the progress path never needed
    anyway -- the base ELF is a relocatable link carrying no addresses, and
    objdiff pairs symbols by name.

    Symbols are classified the way base.ld routes them, by section flags and
    never by name: `i.png_sig_cmp` (AX) and `i.png_libpng_ver` (WA) are
    indistinguishable otherwise. Two kinds are dropped. Anything outside an
    allocatable section is debug bookkeeping (armcc's `__ARM_grp_.debug_frame$5`
    and friends), and zero-initialised data has no bytes to compare -- claiming
    it would only add unmatchable length to the target side.
    """
    try:
        data = obj_path.read_bytes()
    except (OSError, ValueError):
        return {}
    if len(data) < 0x34 or data[:4] != b'\x7fELF':
        return {}

    reader = BinaryReader(obj_path.name, data)
    reader.seek(0x20)
    shoff = reader.read_u32()
    reader.seek(0x30)
    shnum = reader.read_u16()
    shstrndx = reader.read_u16()
    if shstrndx >= shnum:
        return {}

    SHT_SYMTAB = 2
    SHT_NOBITS = 8
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    STT_OBJECT = 1
    STT_FUNC = 2
    SHN_LORESERVE = 0xFF00

    sections = []
    symtab = None
    for i in range(shnum):
        reader.seek(shoff + 0x28 * i + 0x04)
        sec = (reader.read_u32(),)               # type
        reader.seek(shoff + 0x28 * i + 0x08)
        sec += (reader.read_u32(),)              # flags
        reader.seek(shoff + 0x28 * i + 0x10)
        sec += (reader.read_u32(), reader.read_u32(), reader.read_u32())
        sections.append(sec)                     # off, size, link
        if sec[0] == SHT_SYMTAB and symtab is None:
            symtab = (i, sec[2], sec[3], sec[4])

    if symtab is None:
        return {}
    _, sym_off, sym_size, strtab_idx = symtab
    if strtab_idx >= shnum:
        return {}
    reader.seek(sections[strtab_idx][2])
    strtab = reader.read_bytes(sections[strtab_idx][3])

    # Collected per section so extents can be measured against the neighbour
    # that follows, which is the only thing that bounds a symbol once several
    # of them share one section.
    by_section: dict[int, list[tuple[int, str, int]]] = {}
    for j in range(sym_size // 0x10):
        reader.seek(sym_off + 0x10 * j)
        name_off = reader.read_u32()
        value = reader.read_u32()
        size = reader.read_u32()
        info = reader.read_u8()
        reader.read_u8()
        shndx = reader.read_u16()

        if info & 0xF not in (STT_OBJECT, STT_FUNC):
            continue
        if shndx == 0 or shndx >= min(shnum, SHN_LORESERVE):
            continue
        name = get_name(strtab, name_off) if name_off < len(strtab) else ''
        if not name:
            continue
        # A Thumb function carries its mode in bit 0 of the value; that bit is
        # not part of the offset and would put every extent one byte short.
        by_section.setdefault(shndx, []).append((value & ~1, name, size))

    found: dict[str, SymbolInfo] = {}
    for shndx, entries in by_section.items():
        sec_type, flags, _off, sec_size, _link = sections[shndx]
        if not flags & SHF_ALLOC:
            continue
        if flags & SHF_EXECINSTR:
            segment = '.text'
        elif sec_type == SHT_NOBITS:
            continue
        elif flags & SHF_WRITE:
            segment = '.data'
        else:
            segment = '.rodata'

        entries.sort()
        for idx, (value, name, size) in enumerate(entries):
            end = entries[idx + 1][0] if idx + 1 < len(entries) else sec_size
            found[name] = SymbolInfo(segment, size, max(end - value, size))
    return found


def _load_sym_addrs(csv_path: Path, base_addr: int) -> dict[str, int]:
    import csv
    addrs = {}
    reader = csv.DictReader(csv_path.read_text().splitlines())
    for line in reader:
        try:
            addr = int(line["Location"], 16) - base_addr
            addrs[line["Name"]] = addr
        except (ValueError, KeyError):
            pass
    return addrs
