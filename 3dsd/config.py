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

# Referenced dependencies live at deps/<name>, and their sources are keyed
# under this prefix so they cannot collide with a path under src/<binary>/.
DEPS_DIR = 'deps'
DEP_PREFIX = '_deps'


class Dependency:
    """An external source tree referenced by the project, rooted at deps/<name>.

    Nothing is assumed about the repository behind it -- no manifest, no
    layout convention, no scanning. Which directories hold sources, which hold
    headers, and how each file is compiled are all declared by the consuming
    project in cc.yaml, which is what allows an arbitrary upstream repo to be
    used unmodified.
    """

    def __init__(self, name: str, root: Path, source_dirs: list[str],
                 include_dirs: list[str], cc_entry: dict):
        self.name = name
        self.root = root
        self.source_dirs = source_dirs
        self.include_dirs = include_dirs
        self.cc_entry = cc_entry
        self.revision: str | None = None

    def src_key(self, path: Path) -> str:
        """Key a file as `_deps/<name>/<path below the dependency root>`."""
        return f'{DEP_PREFIX}/{self.name}/{path.relative_to(self.root).as_posix()}'

    def rel_files(self) -> list[str]:
        """Every compilable file under the declared source directories."""
        found = []
        for d in self.source_dirs:
            base = self.root / d if d not in ('.', '') else self.root
            if not base.is_dir():
                raise Exception(
                    f"Dependency '{self.name}': source directory '{d}' does not "
                    f"exist under {self.root.as_posix()}")
            found += [f.relative_to(self.root).as_posix()
                      for f in base.rglob('*') if f.suffix in SOURCE_SUFFIXES]
        return sorted(set(found))


SOURCE_SUFFIXES = {'.c', '.cpp', '.s', '.S'}


class ProjectConfig:
    """Loaded project state: binaries, symbols, sources, compiler config, paths."""

    def __init__(self, working_dir: Path, originals: list[Path],
                 exheader: ExHeader | None,
                 binaries: dict[str, CTRBinary],
                 sources: dict[str, list[Path]],
                 build_dir: Path, split_dir: Path, link_dir: Path,
                 out_dir: Path, tool_dir: Path,
                 symbols: dict[str, list[Symbol]],
                 cc_info: dict, compilers: dict[str, str] | None = None,
                 deps: dict[str, "Dependency"] | None = None):
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
        self.deps = deps or {}
        self._verified_ccs: set[str] = set()
        # {binary: {symbol: compiled section length}}, filled by get_source_map
        # and read by the ninja generator to size the comparison window.
        self._compiled_sizes: dict[str, dict[str, int]] = {}

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
        # Popped before _resolve_cc_info so `dependencies:` is never mistaken for
        # a binary entry, exactly as `compilers:` is.
        deps = _load_deps(cc_info.pop('dependencies', None), working_dir)
        cc_info = _resolve_cc_info(cc_info, source_dir, deps)
        sources = _gather_sources(source_dir, cc_info, single_binary)
        _add_dep_sources(sources, cc_info, deps, binaries, single_binary)

        symbols: dict[str, list[Symbol]] = {}
        for f in sym_dir.iterdir():
            if not f.is_file():
                continue
            if single_binary and single_binary not in f.name:
                continue
            sym_list = _gather_symbols(f)
            bin_name = f.stem
            # Before the addresses go relative, so the report quotes the same
            # addresses the CSV and Ghidra do.
            _check_unique_names(f, sym_list)
            if bin_name in binaries:
                for sym in sym_list:
                    sym.addr -= binaries[bin_name].base_addr
            symbols[bin_name] = sym_list

        return cls(working_dir, originals, exh, binaries, sources,
                   build_dir, split_dir, link_dir, out_dir, tool_dir, symbols,
                   cc_info, compilers, deps)

    def src_key(self, binary_name: str, path: Path) -> str:
        """Identify a source by its path relative to `src/<binary>/`.

        Two files with the same name in different directories -- or a `.c` and
        a `.cpp` sharing a stem -- are different translation units, so the
        relative path, not the stem, is what keys compiler config, object
        paths and the source map.
        """
        for dep in self.deps.values():
            try:
                return dep.src_key(path)
            except ValueError:
                continue
        try:
            return path.relative_to(self.working_dir / 'src' / binary_name).as_posix()
        except ValueError:
            return path.name

    def get_cc(self, binary_name: str, source_name: str) -> tuple[Path, list[str]]:
        """Return (compiler_path, flags) for a source, keyed by `src_key`.

        Falls back to the bare file name so cc.yaml may name a file without
        spelling out the directory it sits in.
        """
        dep = self._dependency_of(source_name)
        if dep is not None:
            # A dependency file is configured by its own cc.yaml section, keyed
            # on the path below the dependency root.
            rel = source_name[len(f'{DEP_PREFIX}/{dep.name}/'):]
            entries = dep.cc_entry
        else:
            entries = self.cc_info.get(binary_name)
            entries = entries if isinstance(entries, dict) else {}
            rel = source_name

        d = entries.get(rel) or entries.get(rel.rsplit('/', 1)[-1])
        if not d:
            d = self.cc_info.get('default')
        if not d:
            raise Exception(f"No compiler config for {source_name} and no default!")
        cc_name = d['cc']
        flags = list(d.get('flags', []))

        # Every source built for this binary can include the headers of every
        # dependency the binary declares, so game code reaches its headers and
        # one dependency reaches another's.
        for consumed in _binary_deps(self.cc_info, binary_name, self.deps):
            for inc in consumed.include_dirs:
                rel_inc = (consumed.root / inc).relative_to(self.working_dir)
                flags.append(f'-I{rel_inc.as_posix()}')

        if cc_name in self.compilers:
            # A relative install path is relative to the project, not to
            # wherever the command happened to be run from -- otherwise
            # `compilers: {name: deps/armcc_4.1_1049}` only resolves when the
            # shell is already sitting in the project directory.
            install = Path(self.compilers[cc_name])
            if not install.is_absolute():
                install = self.working_dir / install
            cc = install / 'bin' / 'armcc.exe'
            if not cc.exists():
                cc = install / 'bin' / 'armcc'
            if not cc.exists():
                raise Exception(
                    f"Compiler '{cc_name}': no armcc executable found under {install.resolve() / 'bin'}")
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
                        f"Compiler '{cc_name}': no armcc executable in {install.resolve() / 'bin'}")
                include = install / 'include'
                if include.is_dir():
                    flags.append(f'-I{include.as_posix()}')
            elif (found := _find_executable(cc)) is not None:
                cc = found
            else:
                raise Exception(
                    f"Compiler '{cc_name}' not found in {self.tool_dir}.\n"
                    f"  Set its install directory in cc.yaml, e.g.:\n"
                    f"  compilers:\n"
                    f"    {cc_name}: C:/path/to/armcc/4.1/b1049")

        self._verify_cc(cc_name, cc)
        return cc, flags

    def _dependency_of(self, src_key: str) -> "Dependency | None":
        """The dependency a `_deps/<name>/...` key belongs to, if any."""
        if not src_key.startswith(f'{DEP_PREFIX}/'):
            return None
        name = src_key.split('/', 2)[1]
        return self.deps.get(name)

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
        from .compare import compile_source, discover_sections, discover_section_sizes

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
        sizes_by_key: dict[str, dict[str, int]] = {}
        for key in sorted(sources):
            build_o = self.obj_path(bin_name, key)
            sizes_by_key[key] = discover_section_sizes(build_o)
            if build_o.exists() and build_o.stat().st_size > 0:
                found = [sanitize(s) for s in discover_sections(build_o)]
                # A dependency file contributing nothing is normal -- a game uses
                # a fraction of a shared library, and plenty of it compiles
                # away entirely behind #ifdefs. Only the project's own sources
                # are worth warning about; dependencies get a summary instead.
                if (not found and sanitize(sources[key].stem) not in all_syms
                        and not key.startswith(f'{DEP_PREFIX}/')):
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
        #
        # The project's own sources go first in both passes: a vendored file
        # must never take a symbol away from the file the project wrote for it.
        # Sort order cannot express this -- '_' falls between the upper and
        # lower case letters -- so the two origins are partitioned explicitly.
        own = sorted(k for k in sources if not k.startswith(f'{DEP_PREFIX}/'))
        vendored = sorted(k for k in sources if k.startswith(f'{DEP_PREFIX}/'))
        for group in (own, vendored):
            for key in group:
                claim(sanitize(sources[key].stem), key)
            for key in group:
                for sym in discovered[key]:
                    claim(sym, key)

        # Record how long each claimed symbol is once compiled. A function's
        # literal pool lives at the end of its own section, so this is often
        # longer than the size the symbol CSV gives.
        compiled = self._compiled_sizes.setdefault(bin_name, {})
        for sym, key in owner.items():
            by_sym = sizes_by_key.get(key) or {}
            size = by_sym.get(sym, by_sym.get('.text'))
            if size:
                compiled[sym] = size

        self._report_deps(bin_name, vendored, discovered, owner)
        return result

    def compiled_size(self, bin_name: str, sym: str) -> int | None:
        """Length of `sym` as the compiler emits it, if it has been discovered."""
        return self._compiled_sizes.get(bin_name, {}).get(sym)

    def _report_deps(self, bin_name: str, vendored: list[str],
                          discovered: dict[str, list[str]], owner: dict[str, str]):
        """One summary line per dependency, instead of per-file warnings.

        A dependency usually defines far more than any one game uses, so a file
        that claims nothing is normal and not worth warning about. The counts
        are still worth printing: a dependency contributing zero almost always
        means the binary's CSV does not use its symbol names, which
        is otherwise invisible.
        """
        for name, dep in self.deps.items():
            prefix = f'{DEP_PREFIX}/{name}/'
            keys = [k for k in vendored if k.startswith(prefix)]
            if not keys:
                continue
            found = len({s for k in keys for s in discovered[k]})
            claimed = sum(1 for k in owner.values() if k.startswith(prefix))
            rev = f' @{dep.revision}' if dep.revision else ''
            print(f"  {name}{rev}: {claimed} of {found} discovered symbols "
                  f"are in symbols/{bin_name}.csv")

def _check_unique_names(sym_path: Path, symbols: list[Symbol]) -> None:
    """Reject a symbol CSV that names two symbols the same.

    A name is a symbol's identity throughout the pipeline: it becomes the split
    object's filename and the symbol written inside it. Duplicates are quietly
    destructive -- each one overwrites the last during the split, so the
    original bytes of every symbol but the final one go missing -- and then the
    link is handed the same object once per occurrence and fails with a
    `multiple definition` naming one file on both sides.

    Names are compared after `sanitize`, which is what actually reaches the
    filesystem: two names that differ only in characters sanitize rewrites
    would collide just as destructively.
    """
    groups: dict[str, list[Symbol]] = {}
    for sym in symbols:
        groups.setdefault(sanitize(sym.name), []).append(sym)
    clashes = sorted((g for g in groups.values() if len(g) > 1),
                     key=len, reverse=True)
    if not clashes:
        return

    total = sum(len(g) for g in clashes)
    lines = [
        f"Duplicate symbol names in {sym_path.name}: "
        f"{total:,} symbols share {len(clashes):,} names.",
        "  A name is a symbol's identity here: it becomes the split object's",
        "  filename and the symbol inside it. Duplicates overwrite each other",
        "  during the split -- losing the original bytes of all but the last --",
        "  and then hand ld the same object once per occurrence.",
    ]
    for group in clashes[:10]:
        names = sorted({s.name for s in group})
        shown = names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1} more)"
        addrs = ", ".join(f"{s.addr:08x}" for s in group[:2])
        lines.append(f"    {len(group):6,}x  {shown}   (e.g. {addrs})")
    if len(clashes) > 10:
        lines.append(f"    ... and {len(clashes) - 10:,} more")
    lines += [
        "  Fix this in the export. Give them the names the compiler emits --",
        "  RTTI vtables and typeinfo mangle as _ZTV<class> / _ZTI<class> -- or",
        "  leave labels that cannot be named uniquely out of the CSV entirely:",
        "  the pipeline already covers unnamed regions by address.",
    ]
    raise Exception('\n'.join(lines))


def _load_deps(dep_info: dict, working_dir: Path) -> dict[str, "Dependency"]:
    """Build the Dependency objects declared under cc.yaml's `dependencies:` key."""
    deps: dict[str, Dependency] = {}
    for name, entry in (dep_info or {}).items():
        if not isinstance(entry, dict):
            raise Exception(
                f"Dependency '{name}' in cc.yaml must be a mapping, not "
                f"{type(entry).__name__}.")

        root = working_dir / DEPS_DIR / name
        if not root.is_dir():
            raise Exception(
                f"Dependency '{name}' is declared in cc.yaml but "
                f"{root.as_posix()} does not exist.\n"
                f"  If it is a git submodule, initialise it:\n"
                f"    git submodule update --init {DEPS_DIR}/{name}")
        # Dotfiles do not count: a directory kept in git by a lone .gitkeep,
        # with the real contents ignored or not yet checked out, is empty for
        # every purpose that matters here.
        if not any(p for p in root.iterdir() if not p.name.startswith('.')):
            raise Exception(
                f"Dependency '{name}' at {root.as_posix()} is empty -- this is "
                f"usually an uninitialised submodule.\n"
                f"  Populate it with:\n"
                f"    git submodule update --init {DEPS_DIR}/{name}")
        # Flags reach the compile rule comma-joined and are split back on ','
        # (ninja.py / __main__.py), so a comma in an -I path would silently
        # tear the command line in half.
        if ',' in root.as_posix():
            raise Exception(
                f"Dependency '{name}': the path {root.as_posix()} contains a "
                f"comma, which cannot be passed through the compile rule's "
                f"flag list. Rename the directory.")

        if 'sources' not in entry:
            raise Exception(
                f"Dependency '{name}' must declare `sources:` -- a list of "
                f"directories under {DEPS_DIR}/{name} to compile (use [] for a "
                f"headers-only reference). Nothing is inferred from the "
                f"dependency's own layout.")
        source_dirs = list(entry.pop('sources') or [])
        include_dirs = list(entry.pop('include', None) or [])
        for d in include_dirs:
            if not (root / d).is_dir():
                raise Exception(
                    f"Dependency '{name}': include directory '{d}' does not exist "
                    f"under {root.as_posix()}")

        dep = Dependency(name, root, source_dirs, include_dirs, entry)
        dep.revision = _git_revision(root)
        deps[name] = dep
    return deps


def _git_revision(root: Path) -> str | None:
    """Short HEAD of a checkout, or None. Read-only and best-effort."""
    try:
        r = subprocess.run(['git', '-C', str(root), 'rev-parse', '--short', 'HEAD'],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def _binary_deps(cc_info: dict, bin_name: str,
                      deps: dict[str, "Dependency"]) -> list["Dependency"]:
    """The dependencies a binary declares it consumes, in declaration order."""
    entry = cc_info.get(bin_name)
    if not isinstance(entry, dict):
        return []
    names = entry.get('dependencies') or []
    if isinstance(names, str):
        names = [names]
    out = []
    for n in names:
        if n not in deps:
            raise Exception(
                f"Binary '{bin_name}' lists dependency '{n}', which is not "
                f"declared under cc.yaml's `dependencies:` key.")
        out.append(deps[n])
    return out


def _find_executable(path: Path) -> Path | None:
    """Locate a tools/ executable given the bare name from cc.yaml.

    Not `with_suffix('.exe')`: every armcc name carries dots, so
    `armcc_4.1_894` would be read as stem `armcc_4` plus extension `.1_894`
    and the check would look for `armcc_4.exe`. The name is extended instead.

    Toolchains are often shipped with both a Windows and an extensionless
    Unix binary side by side, so the platform decides which one wins rather
    than whichever happens to be tested first.
    """
    exe = path.with_name(path.name + '.exe')
    order = (exe, path) if os.name == 'nt' else (path, exe)
    return next((p for p in order if p.is_file()), None)


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
        if (sub_dir / DEP_PREFIX).exists():
            raise Exception(
                f"{sub_dir.as_posix()}/{DEP_PREFIX} is reserved: referenced "
                f"dependency sources are keyed under '{DEP_PREFIX}/'. Rename it.")

        objects[sub_dir.name] = [
            p for p in sub_dir.rglob('*')
            if p.suffix in SOURCE_SUFFIXES and p not in ignored
        ]
    return objects


def _add_dep_sources(sources: dict[str, list[Path]], cc_info: dict,
                         deps: dict[str, "Dependency"], binaries: dict,
                         module: str = None):
    """Add each binary's declared dependencies to its source list, in place.

    A dependency serving several binaries is compiled once per binary, as each
    binary has its own symbol CSV and its own objects under build/<binary>/.
    """
    for bin_name in binaries:
        if module and bin_name != module:
            continue
        for dep in _binary_deps(cc_info, bin_name, deps):
            ignored = set()
            for pat in dep.cc_entry.get('ignored', []):
                ignored.update(f for f in dep.rel_files() if fnmatch.fnmatch(f, pat))
            files = [dep.root / f for f in dep.rel_files() if f not in ignored]
            sources.setdefault(bin_name, []).extend(files)


# Keys inside a binary or dependency entry that configure the entry itself
# rather than naming a source file.
_ENTRY_KEYWORDS = {'ignored', 'dependencies'}


def _resolve_cc_info(cc_info: dict, src_dir: Path,
                     deps: dict[str, "Dependency"] | None = None) -> dict:
    """Resolve preset definitions and wildcard patterns in cc.yaml.

    Dependency entries are expanded by the same code as binary entries, so a
    dependency supports `presets:`, `ignored:`, wildcards and per-file settings
    with no separate configuration vocabulary -- the only difference is that
    its paths are relative to the dependency root instead of src/<binary>/.
    """
    preset_defs = cc_info.pop('presets', {})

    for binary_name, binary_dict in cc_info.items():
        if binary_name == 'default' or not isinstance(binary_dict, dict):
            continue
        binary_src_dir = src_dir / binary_name

        def _files(d=binary_src_dir):
            if not d.is_dir():
                return []
            return [f.relative_to(d).as_posix() for f in d.rglob('*') if f.is_file()]

        _expand_entry(binary_name, binary_dict, preset_defs, _files)

    for dep in (deps or {}).values():
        _expand_entry(dep.name, dep.cc_entry, preset_defs, dep.rel_files)

    return cc_info


def _expand_entry(name: str, entry: dict, preset_defs: dict, files_fn):
    """Turn an entry's presets and wildcards into concrete per-file configs.

    `files_fn` is called only when there is something to expand, so an entry
    with no presets or globs never walks the filesystem.
    """
    file_presets = entry.pop('presets', None)
    ignored_patterns = entry.get('ignored')

    wildcard_keys = [
        k for k in entry
        if k not in _ENTRY_KEYWORDS and any(c in k for c in '*?[')
    ]
    if not file_presets and not wildcard_keys:
        return

    src_files = files_fn()

    ignored: set[str] = set()
    if ignored_patterns:
        for pat in ignored_patterns:
            ignored.update(f for f in src_files if fnmatch.fnmatch(f, pat))

    expansions: list[tuple[str, dict]] = []
    if file_presets:
        for preset_name, file_list in file_presets.items():
            preset = preset_defs.get(preset_name)
            if not preset:
                raise ValueError(f"Preset '{preset_name}' in '{name}' not defined!")
            for pattern in file_list:
                expansions.append((pattern, preset))
    for pattern in wildcard_keys:
        expansions.append((pattern, entry.pop(pattern)))

    for pattern, config in expansions:
        is_glob = any(c in pattern for c in '*?[')
        if is_glob:
            for match in src_files:
                if fnmatch.fnmatch(match, pattern) and match not in ignored:
                    # Keyed on the path relative to the entry's root, so two
                    # same-named files in different folders stay distinct.
                    if match not in entry:
                        entry[match] = config
        else:
            if pattern not in entry and pattern not in ignored:
                entry[pattern] = config
