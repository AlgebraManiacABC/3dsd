import shutil
import subprocess
from pathlib import Path

from .elf import ELF
from .util import BinaryReader, get_name


def compile_source(source: Path, output: Path, cc: Path, flags: list[str]):
    """Compile a translation unit. Writes an empty file on failure so the
    build can continue (comparison then falls back to the split object)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(cc)] + flags + ['-c', str(source), '-o', str(output)]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        output.write_bytes(b'')


def extract_and_compare(compiled: Path, split: Path, output: Path, sym: str,
                        symbols_csv: Path | None, base_addr: int,
                        split_addr: int) -> bool:
    """Compare one function from a compiled TU against its split object.

    The output object always gets the split (original) bytes so the final
    link stays byte-perfect. The comparison result is reported separately by
    objdiff, which diffs the target and base ELFs; nothing here records it.
    """
    output.parent.mkdir(parents=True, exist_ok=True)

    matched = False
    if compiled.exists() and compiled.stat().st_size > 0:
        compiled_elf = ELF.from_section(compiled, sym)
        if compiled_elf is not None:
            split_elf = ELF.from_path(split)
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


def discover_sections(obj_path: Path) -> list[str]:
    """Read an ELF .o and return all function names with 'i.' sections
    (created by armcc --split_sections)."""
    try:
        data = obj_path.read_bytes()
    except (OSError, ValueError):
        return []
    if len(data) < 0x34 or data[:4] != b'\x7fELF':
        return []

    reader = BinaryReader(obj_path.name, data)
    reader.seek(0x20)
    shoff = reader.read_u32()
    reader.seek(0x30)
    shnum = reader.read_u16()
    shstrndx = reader.read_u16()

    if shstrndx >= shnum:
        return []

    reader.seek(shoff + 0x28 * shstrndx + 0x10)
    shstrtab_off = reader.read_u32()
    reader.seek(shoff + 0x28 * shstrndx + 0x14)
    shstrtab_size = reader.read_u32()
    reader.seek(shstrtab_off)
    shstrtab = reader.read_bytes(shstrtab_size)

    names = []
    for i in range(shnum):
        reader.seek(shoff + 0x28 * i)
        name_off = reader.read_u32()
        name = get_name(shstrtab, name_off) if name_off < len(shstrtab) else ''
        if name.startswith('i.'):
            names.append(name[2:])
    return names


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
