"""build.ninja generation."""

import sys
from pathlib import Path

from .config import ProjectConfig
from .ctrtype import CTRBinary
from .util import Symbol, posix, sanitize

_PACKAGE_DIR = Path(__file__).parent
_LINKER_LD = _PACKAGE_DIR / 'linker.ld'
_BASE_LD = _PACKAGE_DIR / 'base.ld'
_LD_FLAGS = '--entry=0 --no-warn-mismatch --use-blx -T $linker_ld'

_RULES = [
    '# === Rules ===',
    '',
    'rule compile',
    '  command = $tool compile --source $in --output $out --cc $cc_path $flags_arg',
    '  description = CC $desc',
    '',
    'rule link',
    '  command = $ld $ldflags @$out.rsp -o $out -Map $out.map',
    '  rspfile = $out.rsp',
    '  rspfile_content = $in_newline',
    '  description = LINK $out',
    '',
    'rule to_binary',
    '  command = $objcopy $in -O binary $out',
    '  description = BIN $out',
    '',
    'rule cro_from_elf',
    ('  command = $tool cro-from-elf --linked $in --original $original --output $out'
     ' --objcopy $objcopy'),
    '  description = CRO $out',
    '',
    'rule link_base',
    '  command = $tool link-base --ld $ld --output $out --rsp $out.rsp',
    '  rspfile = $out.rsp',
    '  rspfile_content = $in_newline',
    '  description = LINK_BASE $out',
    '',
    'rule verify',
    '  command = $tool check-file --original $original --built $in --stamp $out',
    '  description = VERIFY $desc',
    '',
]


def _escape_ninja(s: str) -> str:
    return s.replace('$', '$$').replace(' ', '$ ').replace(':', '$:')


def _escape_all(paths: list[str]) -> str:
    return ' '.join(_escape_ninja(p) for p in paths)


def _split_names(symbols: list[Symbol], bin_size: int):
    """Yield the name of every split object, in address order.

    Named symbols give their sanitized name; each unnamed stretch between
    them is named after its address. Together they cover the binary end to
    end, exactly as `split_binary` cuts it.
    """
    sym_dict = {sym.addr: sym for sym in symbols if sym.addr >= 0}
    addrs = sorted(sym_dict)
    cur_addr = 0
    addr_idx = 0
    while addr_idx < len(addrs) or cur_addr < bin_size:
        if addr_idx >= len(addrs):
            yield f'{cur_addr:08x}'
            cur_addr = bin_size
        elif cur_addr == addrs[addr_idx]:
            sym = sym_dict[cur_addr]
            next_addr = addrs[addr_idx + 1] if addr_idx + 1 < len(addrs) else bin_size
            yield sanitize(sym.name)
            cur_addr += min(sym.size, next_addr - cur_addr)
            addr_idx += 1
        elif cur_addr < addrs[addr_idx]:
            yield f'{cur_addr:08x}'
            cur_addr = addrs[addr_idx]
        else:
            raise RuntimeError(f"Address tracking error at {cur_addr:08x}")


class _NinjaWriter:
    """Accumulates build.ninja lines and the targets the phony rules need."""

    def __init__(self, config: ProjectConfig, roundtrip: bool):
        self.config = config
        self.roundtrip = roundtrip
        self.lines: list[str] = []
        self.default_targets: list[str] = []
        self.compile_targets: list[str] = []
        self.base_elf_targets: list[str] = []

    def rel(self, p: Path) -> str:
        """Make a path relative to working_dir for the ninja file."""
        try:
            return posix(p.relative_to(self.config.working_dir))
        except ValueError:
            return posix(p)

    def emit(self, *lines: str):
        self.lines.extend(lines)

    def binary(self, bin_name: str, binary: CTRBinary):
        """Emit every build statement for one binary."""
        config = self.config
        self.emit(f'# === {bin_name} ===', '')

        source_map = config.get_source_map(bin_name)
        names = list(_split_names(config.symbols.get(bin_name, []), len(binary.data)))

        # One compile per source that claims at least one symbol, in the order
        # its first symbol appears in the binary -- which is also the order the
        # base ELF links them in.
        compiled_objects: list[str] = []
        emitted: set[str] = set()
        for name in names:
            if name not in source_map:
                continue
            src_path, src_key = source_map[name]
            if src_key in emitted:
                continue
            emitted.add(src_key)
            build_o = self.rel(config.obj_path(bin_name, src_key))
            compiled_objects.append(build_o)
            self.compile_targets.append(build_o)
            self._compile(bin_name, src_path, src_key, build_o)

        # The objdiff base ELF is the progress path: compiled objects only.
        if compiled_objects:
            base_elf = self.rel(config.out_dir / 'objdiff_base' / bin_name)
            # base.ld decides which sections the base ends up with, so editing
            # it has to relink. Without this the old base survives and pairs
            # against sections the new script no longer emits -- a data section
            # renamed here read as 0% matched until a full clean, with nothing
            # to suggest the base was stale.
            self.emit(f'build {_escape_ninja(base_elf)}: link_base '
                      f'{_escape_all(compiled_objects)} | {_escape_ninja(_BASE_LD.as_posix())}',
                      '')
            self.base_elf_targets.append(base_elf)
            self.default_targets.append(base_elf)

        if self.roundtrip:
            self._relink(bin_name, [self.rel(config.split_dir / bin_name / f'{name}.o')
                                    for name in names])

    def _compile(self, bin_name: str, src_path: Path, src_key: str, build_o: str):
        cc_path, flags = self.config.get_cc(bin_name, src_key)
        flags_arg = '--flags=' + ','.join(flags) if flags else ''
        self.emit(f'build {_escape_ninja(build_o)}: compile {_escape_ninja(self.rel(src_path))}',
                  f'  cc_path = {posix(cc_path.resolve())}',
                  f'  flags_arg = {flags_arg}',
                  f'  desc = {bin_name}/{src_key}',
                  '')

    def _relink(self, bin_name: str, split_objects: list[str]):
        """Link the split originals, flatten to a binary, and verify it.

        Every object here holds original bytes, so this checks the pipeline
        -- the split, the linker script, the CRO rebuild -- and not the decomp.
        The verify stamp is the default target, so a mismatch fails the build.
        """
        config = self.config
        linked = self.rel(config.link_dir / f'{bin_name}_linked')
        self.emit(f'build {_escape_ninja(linked)}: link {_escape_all(split_objects)}',
                  f'  ldflags = {_LD_FLAGS}',
                  '')

        orig_file = next((p for p in config.originals if p.name == bin_name), None)
        final_bin = self.rel(config.out_dir / bin_name)
        if '.cro' in bin_name:
            if orig_file is None:
                raise RuntimeError(f"No original for {bin_name} in {config.originals}")
            self.emit(f'build {_escape_ninja(final_bin)}: cro_from_elf {_escape_ninja(linked)}',
                      f'  original = {self.rel(orig_file)}',
                      '')
        else:
            self.emit(f'build {_escape_ninja(final_bin)}: to_binary {_escape_ninja(linked)}',
                      '')

        if orig_file is None:
            self.default_targets.append(final_bin)
            return
        original = self.rel(orig_file)
        stamp = self.rel(config.out_dir / f'{bin_name}.verified')
        self.emit(f'build {_escape_ninja(stamp)}: verify {_escape_ninja(final_bin)}'
                  f' | {_escape_ninja(original)}',
                  f'  original = {original}',
                  f'  desc = {bin_name}',
                  '')
        self.default_targets.append(stamp)

    def phonies(self):
        """The `compile` and `objdiff` aliases and the default targets."""
        if self.compile_targets:
            self.emit(f'build compile: phony {_escape_all(self.compile_targets)}', '')
        if self.base_elf_targets:
            self.emit(f'build objdiff: phony {_escape_all(self.base_elf_targets)}', '')
        if self.default_targets:
            self.emit(f'default {_escape_all(self.default_targets)}', '')


def generate_ninja(config: ProjectConfig, roundtrip: bool = False):
    """Generate build.ninja for the project.

    By default the graph carries only what decomp progress needs: each source
    compiled to its own object, and those objects linked into the objdiff base
    ELF. The objdiff target is built from the original binary and the symbol
    CSV, so nothing in the progress path needs the split.

    `roundtrip` adds the byte-perfect rebuild on top: every split object
    linked back together, flattened (or rebuilt as a CRO), and hashed against
    the original. That path exercises the pipeline rather than the decomp --
    every object it links holds original bytes -- and it costs a link of every
    symbol in the binary (74,384 objects for ACNL's code.bin), so it is opt-in.
    """
    ninja_path = config.working_dir / 'build.ninja'
    pipeline_dir = _PACKAGE_DIR.parent.resolve()
    python = posix(Path(sys.executable).resolve())

    # '3dsd' is not a valid Python identifier, so the wrapper loads the
    # package via importlib instead of an import statement.
    wrapper = config.build_dir / '_3dsd_wrapper.py'
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        f"import sys, importlib; sys.path.insert(0, {str(pipeline_dir)!r}); "
        f"importlib.import_module('3dsd.__main__').main()\n"
    )
    tool_cmd = f'"{python}" "{posix(wrapper.resolve())}"'

    (config.out_dir / 'objdiff_base').mkdir(parents=True, exist_ok=True)

    out = _NinjaWriter(config, roundtrip)
    out.emit('# Generated by 3dsd ninja — do not edit',
             'ninja_required_version = 1.3',
             '',
             f'ld = {posix(config.ld_path().resolve())}',
             f'objcopy = {posix(config.objcopy_path().resolve())}',
             f'tool = {tool_cmd}',
             f'linker_ld = {posix(_LINKER_LD.resolve())}',
             '',
             *_RULES)
    for bin_name, binary in config.binaries.items():
        out.binary(bin_name, binary)
    out.phonies()

    ninja_path.write_text('\n'.join(out.lines))
    print(f"Generated {ninja_path}")
    mode = 'progress + byte-perfect round-trip' if roundtrip else 'decomp progress'
    print(f"  Targets: {mode}.")
    print("  Run 'ninja' to build, or 'ninja compile' to compile only.")
