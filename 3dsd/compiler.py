"""Running armcc, and reading back which symbols a compiled object defines."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .elf import ELFHeader, SectionHeaderFlags, SectionHeaderType
from .util import ORANGE, RED, RESET, BinaryReader, get_name, use_color

_GRP_COMDAT = 0x1
_STT_OBJECT = 1
_STT_FUNC = 2
_SHN_LORESERVE = 0xFF00


def compile_source(source: Path, output: Path, cc: Path, flags: list[str],
                   depfile: Path | None = None) -> int:
    """Compile a translation unit as ninja's `compile` rule does; armcc's exit code.

    Prints nothing, one warning tally, or the errors in full (`summarize`).
    A failure leaves no object behind, so ninja fails the step and runs it
    again next time rather than linking something stale."""
    returncode, text = compile_capture(source, output, cc, flags, depfile=depfile)
    report = summarize(source, text, returncode)
    if report:
        print(report, flush=True)
    return returncode


def compile_capture(source: Path, output: Path, cc: Path, flags: list[str],
                    cwd: Path | None = None,
                    depfile: Path | None = None) -> tuple[int, str]:
    """Compile a translation unit; `(returncode, everything armcc printed)`.

    On failure the object is removed. With `depfile`, the headers the source
    included are written there for ninja (`deps = gcc`)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(cc), *flags, '-c', str(source), '-o', str(output)]
    raw_dep = output.with_name(output.name + '.armdep')
    if depfile is not None:
        cmd.append(f'--depend={raw_dep}')
    result = subprocess.run(cmd, cwd=cwd, env=_cc_env(cc), check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace')
    if result.returncode != 0:
        output.unlink(missing_ok=True)
    elif depfile is not None:
        # Written even if armcc wrote nothing: ninja fails a step whose
        # depfile is missing.
        armdep = raw_dep.read_text(errors='replace') if raw_dep.exists() else ''
        depfile.write_text(_ninja_depfile(output, armdep))
    raw_dep.unlink(missing_ok=True)
    return result.returncode, result.stdout


def _ninja_depfile(output: Path, armdep: str) -> str:
    """armcc's `--depend` output rewritten as one Makefile rule ninja can read.

    armcc writes one `target: dependency` line per file, quoting or escaping
    spaces depending on `--depend_format`; each path is taken whole after the
    first `: ` (a drive letter's colon has no space after it) and re-escaped.
    """
    deps = []
    for line in armdep.splitlines():
        _target, sep, dep = line.partition(': ')
        dep = dep.strip().strip('"').replace('\\ ', ' ')
        if sep and dep:
            deps.append(dep.replace('\\', '/'))
    escaped = (d.replace('$', '$$').replace('#', '\\#').replace(' ', '\\ ') for d in deps)
    return f"{output.as_posix()}: {' '.join(escaped)}\n"


def describe(source: Path, text: str, returncode: int) -> str:
    """Everything a compile printed, its tally coloured: what a partial build
    shows, where the warnings are few enough to be worth reading.

    armcc ends with its own tally (`foo.c: 1 warning, 0 errors`), which is
    coloured in place; one is added when it is missing. Errors are red
    throughout, as in a full build.
    """
    warnings, errors = count_diagnostics(text)
    failed = errors or returncode != 0
    if not failed and not warnings:
        return f'{source.as_posix()}: ok'
    lines = text.rstrip().splitlines()
    if not lines or not _SUMMARY.search(lines[-1]):
        lines.append(f"{source.as_posix()}: {warnings} warning{'s' if warnings != 1 else ''}, "
                     f"{errors} error{'s' if errors != 1 else ''}")
    if not use_color():
        return '\n'.join(lines)
    if failed:
        return f"{RED}{chr(10).join(lines)}{RESET}"
    return '\n'.join([*lines[:-1], f'{ORANGE}{lines[-1]}{RESET}'])



_SUMMARY = re.compile(r'(\d+) warnings?, (\d+) errors?')


def count_diagnostics(text: str) -> tuple[int, int]:
    """`(warnings, errors)` armcc reported, from its own closing tally.

    armcc ends with `file: 2 warnings, 0 errors`; when that line is missing
    (a crash, a driver error) the individual diagnostics are counted instead.
    """
    tallies = _SUMMARY.findall(text)
    if tallies:
        return (sum(int(w) for w, _ in tallies), sum(int(e) for _, e in tallies))
    warnings = len(re.findall(r':\s+Warning:', text))
    errors = len(re.findall(r':\s+(?:Error|Fatal error):', text))
    return warnings, errors


def summarize(source: Path, text: str, returncode: int) -> str:
    """What a compile prints: nothing, one orange line, or the errors in red.

    Warnings are counted, not shown -- a decompilation produces the same
    implicit-declaration warning thousands of times. Errors are shown in full,
    since they are what a build log is read for. A failed compile with no
    tally (the compiler could not start, say) counts as an error too.
    """
    warnings, errors = count_diagnostics(text)
    color = use_color()
    if errors or returncode != 0:
        body = text.rstrip() or f'{source.as_posix()}: compiler exited with {returncode}'
        return f'{RED}{body}{RESET}' if color else body
    if warnings:
        line = f"{source.as_posix()}: {warnings} warning{'s' if warnings != 1 else ''}"
        return f'{ORANGE}{line}{RESET}' if color else line
    return ''




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


@dataclass(frozen=True)
class SymbolInfo:
    """One symbol a compiled object defines.

    `segment` is where base.ld routes it and `size` is the length the
    compiler declared.

    `vague` marks a definition C++ expects to appear in every translation unit
    that needs it -- a vtable, an RTTI record, a template instantiation, an
    inline function -- and which the linker folds down to one copy. Several
    sources defining it is the language working as specified, not a conflict.
    """
    segment: str
    size: int
    vague: bool = False


@dataclass(frozen=True)
class _Section:
    type: int
    flags: int
    off: int
    size: int
    link: int


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
    if len(data) < ELFHeader.EHSIZE:
        return {}

    reader = BinaryReader(obj_path.name, data)
    header = ELFHeader.from_reader(reader)
    if not header.valid or header.shstrndx >= header.shnum:
        return {}

    sections = _read_sections(reader, header)
    symtab = next((s for s in sections if s.type == SectionHeaderType.SHT_SYMTAB), None)
    if symtab is None or symtab.link >= header.shnum:
        return {}
    strtab_sec = sections[symtab.link]
    reader.seek(strtab_sec.off)
    strtab = reader.read_bytes(strtab_sec.size)
    comdat = _comdat_sections(reader, sections)

    # Grouped by section, in address order within each, so that when two
    # symbols share a name (same-named statics in different functions) the
    # one kept is always the same.
    by_section: dict[int, list[tuple[int, str, int]]] = {}
    for j in range(symtab.size // 0x10):
        reader.seek(symtab.off + 0x10 * j)
        name_off = reader.read_u32()
        value = reader.read_u32()
        size = reader.read_u32()
        info = reader.read_u8()
        reader.read_u8()
        shndx = reader.read_u16()

        if info & 0xF not in (_STT_OBJECT, _STT_FUNC):
            continue
        if shndx == 0 or shndx >= min(header.shnum, _SHN_LORESERVE):
            continue
        name = get_name(strtab, name_off) if name_off < len(strtab) else ''
        if name:
            # Bit 0 of a Thumb function's value is its mode, not its offset.
            by_section.setdefault(shndx, []).append((value & ~1, name, size))

    found: dict[str, SymbolInfo] = {}
    for shndx, entries in by_section.items():
        segment = _segment_of(sections[shndx])
        if segment is None:
            continue
        for _value, name, size in sorted(entries):
            found[name] = SymbolInfo(segment, size, shndx in comdat)
    return found


def _read_sections(reader: BinaryReader, header: ELFHeader) -> list[_Section]:
    sections = []
    for i in range(header.shnum):
        base = header.shoff + header.SHENTSIZE * i
        reader.seek(base + 0x04)
        sec_type = reader.read_u32()
        flags = reader.read_u32()
        reader.seek(base + 0x10)
        off, size, link = reader.read_u32(), reader.read_u32(), reader.read_u32()
        sections.append(_Section(sec_type, flags, off, size, link))
    return sections


def _comdat_sections(reader: BinaryReader, sections: list[_Section]) -> set[int]:
    """Indices of every section that belongs to a COMDAT group.

    A vague-linkage definition goes in its own COMDAT group so the linker can
    keep one copy and drop the rest. The group is the only honest signal that
    a repeated definition is expected: armcc gives `_ZTV7UtlBaseI9DemoActorE`
    STB_GLOBAL binding, indistinguishable from a strong definition, and marks
    only the section it lives in.
    """
    comdat: set[int] = set()
    for sec in sections:
        if sec.type != SectionHeaderType.SHT_GROUP or sec.size < 8:
            continue
        reader.seek(sec.off)
        if reader.read_u32() & _GRP_COMDAT:
            for _ in range(sec.size // 4 - 1):
                comdat.add(reader.read_u32())
    return comdat


def _segment_of(sec: _Section) -> str | None:
    """The base.ld output segment for a section, or None if it is dropped."""
    if not sec.flags & SectionHeaderFlags.SHF_ALLOC:
        return None
    if sec.flags & SectionHeaderFlags.SHF_EXECINSTR:
        return '.text'
    if sec.type == SectionHeaderType.SHT_NOBITS:
        return None
    if sec.flags & SectionHeaderFlags.SHF_WRITE:
        return '.data'
    return '.rodata'
