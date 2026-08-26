import csv
import fnmatch
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from .ctrtype import CTRBinary, CRO, ExHeader
from .util import BinaryReader, Symbol, sanitize

# Generated directory names, relative to the project working directory.
# Shared with clean.py so the two cannot drift apart.
BUILD_DIR = 'build'
SPLIT_DIR = 'split'
LINK_DIR = 'link'
OUT_DIR = 'out'
SYMBOLS_DIR = 'symbols'


class ProjectConfig:
    """Loaded project state: binaries, symbols, sources, compiler config, paths."""

    def __init__(self, working_dir: Path, originals: list[Path],
                 exheader: ExHeader | None,
                 binaries: dict[str, CTRBinary],
                 sources: dict[str, list[Path]],
                 build_dir: Path, split_dir: Path, link_dir: Path,
                 out_dir: Path, tool_dir: Path,
                 symbols: dict[str, list[Symbol]],
                 cc_info: dict, compilers: dict[str, str] | None = None):
        self.working_dir = working_dir
        self.originals = originals
        self.exheader = exheader
        self.binaries = binaries
        self.sources = sources
        self.build_dir = build_dir
        self.split_dir = split_dir
        self.link_dir = link_dir
        self.out_dir = out_dir
        self.tool_dir = tool_dir
        self.symbols = symbols
        self.cc_info = cc_info
        self.compilers = compilers or {}
        self._verified_ccs: set[str] = set()

    @classmethod
    def load(cls, working_dir: Path, single_binary: str = None) -> "ProjectConfig":
        orig_dir = working_dir / 'orig'
        source_dir = working_dir / 'src'
        build_dir = working_dir / BUILD_DIR
        split_dir = working_dir / SPLIT_DIR
        link_dir = working_dir / LINK_DIR
        out_dir = working_dir / OUT_DIR
        tool_dir = working_dir / 'tools'
        sym_dir = working_dir / SYMBOLS_DIR
        cc_path = working_dir / 'cc.yaml'

        _check_dirs(working_dir, orig_dir, tool_dir, sym_dir, cc_path)

        for d in [build_dir, split_dir, link_dir, out_dir]:
            d.mkdir(parents=True, exist_ok=True)

        originals = [f for f in orig_dir.rglob('*') if f.is_file()]
        exh, binaries = _gather_binaries(orig_dir, single_binary)
        cc_info = yaml.safe_load(cc_path.read_text())
        compilers = cc_info.pop('compilers', None) or {}
        cc_info = _resolve_cc_info(cc_info, source_dir)
        sources = _gather_sources(source_dir, cc_info, single_binary)

        symbols: dict[str, list[Symbol]] = {}
        for f in sym_dir.iterdir():
            if not f.is_file():
                continue
            if single_binary and single_binary not in f.name:
                continue
            sym_list = _gather_symbols(f)
            bin_name = f.stem
            if bin_name in binaries:
                for sym in sym_list:
                    sym.addr -= binaries[bin_name].base_addr
            symbols[bin_name] = sym_list

        return cls(working_dir, originals, exh, binaries, sources,
                   build_dir, split_dir, link_dir, out_dir, tool_dir, symbols,
                   cc_info, compilers)

    def src_key(self, binary_name: str, path: Path) -> str:
        """Identify a source by its path relative to `src/<binary>/`.

        Two files with the same name in different directories -- or a `.c` and
        a `.cpp` sharing a stem -- are different translation units, so the
        relative path, not the stem, is what keys compiler config, object
        paths and the source map.
        """
        try:
            return path.relative_to(self.working_dir / 'src' / binary_name).as_posix()
        except ValueError:
            return path.name

    def get_cc(self, binary_name: str, source_name: str) -> tuple[Path, list[str]]:
        """Return (compiler_path, flags) for a source, keyed by `src_key`.

        Falls back to the bare file name so cc.yaml may name a file without
        spelling out the directory it sits in.
        """
        d = None
        if binary_name in self.cc_info and isinstance(self.cc_info[binary_name], dict):
            entries = self.cc_info[binary_name]
            d = entries.get(source_name) or entries.get(source_name.rsplit('/', 1)[-1])
        if not d:
            d = self.cc_info.get('default')
        if not d:
            raise Exception(f"No compiler config for {source_name} and no default!")
        cc_name = d['cc']
        flags = list(d.get('flags', []))

        if cc_name in self.compilers:
            install = Path(self.compilers[cc_name])
            cc = install / 'bin' / 'armcc.exe'
            if not cc.exists():
                cc = install / 'bin' / 'armcc'
            if not cc.exists():
                raise Exception(
                    f"Compiler '{cc_name}': no armcc executable found under {install / 'bin'}")
            include = install / 'include'
            if include.is_dir():
                flags.append(f'-I{include.as_posix()}')
        else:
            cc = self.tool_dir / cc_name
            if cc.is_dir():
                install = cc
                cc = install / 'bin' / 'armcc.exe'
                if not cc.exists():
                    cc = install / 'bin' / 'armcc'
                if not cc.exists():
                    raise Exception(
                        f"Compiler '{cc_name}': no armcc executable in {install / 'bin'}")
                include = install / 'include'
                if include.is_dir():
                    flags.append(f'-I{include.as_posix()}')
            elif not cc.exists() and not cc.with_suffix('.exe').exists():
                raise Exception(
                    f"Compiler '{cc_name}' not found in {self.tool_dir}.\n"
                    f"  Set its install directory in cc.yaml, e.g.:\n"
                    f"  compilers:\n"
                    f"    {cc_name}: C:/path/to/armcc/4.1/b1049")

        self._verify_cc(cc_name, cc)
        return cc, flags

    def _verify_cc(self, cc_name: str, cc_path: Path):
        """Check the compiler binary reports the version encoded in its name."""
        if cc_name in self._verified_ccs:
            return
        m = re.fullmatch(r'armcc_(\d+\.\d+)_(\d+)', cc_name)
        if m:
            version, build = m.groups()
            try:
                r = subprocess.run([str(cc_path), '--vsn'],
                                   capture_output=True, text=True, timeout=30)
            except OSError as e:
                raise Exception(f"Cannot run compiler '{cc_path}': {e}")
            text = (r.stdout or '') + (r.stderr or '')
            reported = text.strip().splitlines()[0] if text.strip() else '(no output)'
            if version not in text or f'Build {build}' not in text:
                raise Exception(
                    f"Compiler version mismatch for '{cc_name}':\n"
                    f"  expected {version} [Build {build}]\n"
                    f"  but {cc_path} reports: {reported}")
        self._verified_ccs.add(cc_name)

    def ld_path(self) -> Path:
        return self.tool_dir / 'ld'

    def objcopy_path(self) -> Path:
        return self.tool_dir / 'objcopy'

    def obj_path(self, bin_name: str, src_key: str) -> Path:
        """Object file for a source, mirroring its position under `src/`.

        The extension is kept before the `.o` so `foo.c` and `foo.cpp` in the
        same directory do not fight over one object.
        """
        return self.build_dir / bin_name / f'{src_key}.o'

    def get_source_map(self, bin_name: str) -> dict[str, tuple[Path, str]]:
        """Return {sym_name: (source_path, src_key)} for every symbol a source
        provides.

        Every source is compiled once and scanned for the `i.NAME` sections
        armcc emits under --split_sections, so a symbol is claimed no matter
        whether it sits alone in a file named after it, among a hundred others
        in one translation unit, or in a C++ file under a mangled name. Objects
        are cached in `build/`; only a missing, stale or differently-configured
        object is recompiled.
        """
        from .compare import compile_source, discover_sections

        sources = {self.src_key(bin_name, s): s
                   for s in self.sources.get(bin_name, [])}
        all_syms = {sanitize(sym.name) for sym in self.symbols.get(bin_name, [])
                    if sym.addr >= 0}

        # The discovery object is also keyed on the compiler and flags: editing
        # cc.yaml must invalidate it, or section discovery silently runs against
        # an object built with the previous settings.
        manifest_path = self.build_dir / bin_name / '.discovery.json'
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            manifest = {}

        stale: list[tuple[str, Path, Path, str]] = []
        for key, src_path in sources.items():
            build_o = self.obj_path(bin_name, key)
            cc_path, flags = self.get_cc(bin_name, key)
            cc_key = f'{cc_path}|{",".join(flags)}'
            if (not build_o.exists()
                    or build_o.stat().st_size == 0
                    or src_path.stat().st_mtime > build_o.stat().st_mtime
                    or manifest.get(key) != cc_key):
                stale.append((key, src_path, build_o, cc_key))

        if stale:
            print(f"  Scanning {len(stale)} source file(s) for symbols...")
            with ThreadPoolExecutor(max_workers=_scan_workers()) as pool:
                futures = []
                for key, src_path, build_o, cc_key in stale:
                    cc_path, flags = self.get_cc(bin_name, key)
                    futures.append(pool.submit(compile_source, src_path, build_o,
                                               cc_path, flags, self.working_dir))
                for f in futures:
                    f.result()
            for key, _src, _o, cc_key in stale:
                manifest[key] = cc_key
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest, indent=1))

        discovered: dict[str, list[str]] = {}
        for key in sorted(sources):
            build_o = self.obj_path(bin_name, key)
            if build_o.exists() and build_o.stat().st_size > 0:
                found = [sanitize(s) for s in discover_sections(build_o)]
                if not found and sanitize(sources[key].stem) not in all_syms:
                    print(f"  Warning: {key} defines no discoverable symbols "
                          f"(no 'i.' sections). Add --split_sections to its "
                          f"cc.yaml flags if it holds more than one function.")
                discovered[key] = found
            else:
                # Compile failed. The file can still claim the symbol it is
                # named after below, so the symbol stays in the build and
                # simply reads as unmatched.
                discovered[key] = []

        result: dict[str, tuple[Path, str]] = {}
        owner: dict[str, str] = {}

        def claim(sym: str, key: str):
            if sym not in all_syms:
                return
            if sym in owner:
                if owner[sym] != key:
                    print(f"  Warning: {sym} is defined by both {owner[sym]} "
                          f"and {key}; keeping {owner[sym]}.")
                return
            owner[sym] = key
            result[sym] = (sources[key], key)

        # A file named after a symbol owns it, even if another translation unit
        # also happens to define it. Only then are the remaining sections of
        # each file handed out, so adding a multi-function file cannot quietly
        # take symbols away from the files dedicated to them.
        for key in sorted(sources):
            claim(sanitize(sources[key].stem), key)
        for key in sorted(sources):
            for sym in discovered[key]:
                claim(sym, key)

        return result


def _scan_workers() -> int:
    """Parallelism for the symbol-discovery compiles."""
    return min(32, (os.cpu_count() or 4) * 2)


def _check_dirs(working_dir: Path, orig_dir: Path, tool_dir: Path,
                sym_dir: Path, cc_path: Path):
    missing = []
    if not orig_dir.exists():
        missing.append('directory "orig"')
    if not tool_dir.exists():
        missing.append('directory "tools"')
    else:
        if not (tool_dir / 'ld').exists() and not (tool_dir / 'ld.exe').exists():
            missing.append('tool "ld"')
        if not (tool_dir / 'objcopy').exists() and not (tool_dir / 'objcopy.exe').exists():
            missing.append('tool "objcopy"')
    if not sym_dir.exists():
        missing.append('directory "symbols"')
    if not cc_path.exists():
        missing.append('compiler configuration "cc.yaml"')
    if missing:
        msg = f"Pipeline incomplete for {working_dir}!"
        msg += "".join(f"\n  Missing {m}" for m in missing)
        raise Exception(msg)


def _gather_binaries(path: Path, module: str = None) -> tuple[ExHeader | None, dict[str, CTRBinary]]:
    binaries = {}
    exh = None
    code_path = None
    for f in path.rglob('*'):
        if not f.is_file():
            continue
        lower = f.name.lower()
        if 'header' in lower:
            exh = ExHeader.from_reader(BinaryReader.from_path(f))
        if module and module not in f.name:
            continue
        if '.cro' in f.name:
            cro = CRO.from_reader(BinaryReader.from_path(f))
            binaries[f.name] = CTRBinary(f.name, cro)
        if 'code' in lower and '.cro' not in f.name:
            code_path = f
    if code_path:
        binaries[code_path.name] = CTRBinary(code_path.name, code_path.read_bytes(), exh)
    return exh, binaries


def _gather_symbols(sym_path: Path) -> list[Symbol]:
    symbols = []
    reader = csv.DictReader(sym_path.read_text().splitlines())
    for line in reader:
        try:
            symbols.append(Symbol(
                int(line["Location"], 16), line["Name"],
                line["Mode"], int(line["Size"], 16), line["Segment"]
            ))
        except (ValueError, KeyError):
            pass
    return symbols


def _gather_sources(src_path: Path, cc_info: dict, module: str = None) -> dict[str, list[Path]]:
    if not src_path.exists():
        return {}
    objects = {}
    for sub_dir in src_path.iterdir():
        if not sub_dir.is_dir() or (module and sub_dir.name != module):
            continue
        d_info = cc_info.get(sub_dir.name) if isinstance(cc_info.get(sub_dir.name), dict) else None
        ignored = set()
        if d_info:
            for pat in d_info.get('ignored', []):
                ignored.update(sub_dir.rglob(pat))
        objects[sub_dir.name] = [
            p for p in sub_dir.rglob('*')
            if p.suffix in {'.c', '.cpp', '.s', '.S'} and p not in ignored
        ]
    return objects


def _resolve_cc_info(cc_info: dict, src_dir: Path) -> dict:
    """Resolve preset definitions and wildcard patterns in cc.yaml."""
    preset_defs = cc_info.pop('presets', {})

    for binary_name, binary_dict in cc_info.items():
        if binary_name == 'default' or not isinstance(binary_dict, dict):
            continue

        file_presets = binary_dict.pop('presets', None)
        ignored_patterns = binary_dict.get('ignored')

        wildcard_keys = [
            k for k in binary_dict
            if k != 'ignored' and any(c in k for c in '*?[')
        ]
        if not file_presets and not wildcard_keys:
            continue

        binary_src_dir = src_dir / binary_name
        if not binary_src_dir.is_dir():
            continue

        src_files = [
            f.relative_to(binary_src_dir).as_posix()
            for f in binary_src_dir.rglob('*') if f.is_file()
        ]

        ignored: set[str] = set()
        if ignored_patterns:
            for pat in ignored_patterns:
                ignored.update(f for f in src_files if fnmatch.fnmatch(f, pat))

        expansions: list[tuple[str, dict]] = []
        if file_presets:
            for name, file_list in file_presets.items():
                preset = preset_defs.get(name)
                if not preset:
                    raise ValueError(f"Preset '{name}' in '{binary_name}' not defined!")
                for entry in file_list:
                    expansions.append((entry, preset))
        for pattern in wildcard_keys:
            expansions.append((pattern, binary_dict.pop(pattern)))

        for pattern, config in expansions:
            is_glob = any(c in pattern for c in '*?[')
            if is_glob:
                for match in src_files:
                    if fnmatch.fnmatch(match, pattern) and match not in ignored:
                        # Keyed on the path relative to src/<binary>/, so two
                        # same-named files in different folders stay distinct.
                        if match not in binary_dict:
                            binary_dict[match] = config
            else:
                if pattern not in binary_dict and pattern not in ignored:
                    binary_dict[pattern] = config

    return cc_info
