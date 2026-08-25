import csv
import fnmatch
import json
import re
import subprocess
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

    def get_cc(self, binary_name: str, source_name: str) -> tuple[Path, list[str]]:
        """Return (compiler_path, flags) for a given source file."""
        d = None
        if binary_name in self.cc_info and isinstance(self.cc_info[binary_name], dict):
            d = self.cc_info[binary_name].get(source_name)
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

    def get_source_map(self, bin_name: str) -> dict[str, tuple[Path, str]]:
        """Return {sym_name: (source_path, file_stem)} for all symbols covered by sources.

        Direct matches (stem == sym_name) are found by name.
        Multi-function files are pre-compiled to discover their i.XXX sections.
        """
        from .compare import compile_source, discover_sections

        sources = {s.stem: s for s in self.sources.get(bin_name, [])}
        all_syms = {sanitize(sym.name) for sym in self.symbols.get(bin_name, []) if sym.addr >= 0}

        result: dict[str, tuple[Path, str]] = {}
        for stem, path in sources.items():
            if stem in all_syms:
                result[stem] = (path, stem)

        unmatched = {stem: path for stem, path in sources.items() if stem not in all_syms}
        if not unmatched:
            return result

        # The discovery object is also keyed on the compiler and flags: editing
        # cc.yaml must invalidate it, or section discovery silently runs against
        # an object built with the previous settings.
        manifest_path = self.build_dir / bin_name / '.discovery.json'
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            manifest = {}
        dirty = False

        for stem, src_path in unmatched.items():
            build_o = self.build_dir / bin_name / f'{stem}.o'
            cc_path, flags = self.get_cc(bin_name, src_path.name)
            cc_key = f'{cc_path}|{",".join(flags)}'
            need_compile = (
                not build_o.exists()
                or build_o.stat().st_size == 0
                or src_path.stat().st_mtime > build_o.stat().st_mtime
                or manifest.get(stem) != cc_key
            )
            if need_compile:
                compile_source(src_path, build_o, cc_path, flags)
                manifest[stem] = cc_key
                dirty = True
            if build_o.exists() and build_o.stat().st_size > 0:
                sections = discover_sections(build_o)
                if not sections:
                    print(f"  Warning: {src_path.name} defines no discoverable symbols "
                          f"(no 'i.' sections). Add --split_sections to its cc.yaml flags "
                          f"if it holds more than one function.")
                for sec_name in sections:
                    sname = sanitize(sec_name)
                    if sname in all_syms and sname not in result:
                        result[sname] = (src_path, stem)

        if dirty:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest, indent=1))

        return result


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
                        key = match.rsplit('/', 1)[-1]
                        if key not in binary_dict:
                            binary_dict[key] = config
            else:
                if pattern not in binary_dict and pattern not in ignored:
                    binary_dict[pattern] = config

    return cc_info
