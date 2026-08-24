from pathlib import Path

from .config import ProjectConfig
from .ctrtype import CTRBinary
from .elf import ELF
from .util import Symbol, sanitize


def split_binary(binary: CTRBinary, split_dir: Path,
                 symbols: list[Symbol], progress: bool = True) -> list[tuple[int, Path]]:
    """Split a binary into per-symbol ELF object files."""
    bin_data = binary.data
    bin_size = len(bin_data)
    symbol_dict = {sym.addr: sym for sym in symbols}
    addrs = sorted([sym.addr for sym in symbols if sym.addr >= 0])
    progress_addrs = set(addrs[i] for i in range(0, len(addrs), max(1, len(addrs) // 100)))
    splat = []
    all_o = []
    total_named = 0
    total_inter = 0
    cur_addr = 0
    last_segment = '.text'

    while addrs or cur_addr < bin_size:
        if progress and cur_addr in progress_addrs:
            print(f"  [SPLIT] {100 * cur_addr / bin_size:.1f}%")

        if not addrs:
            sym_name = f'{cur_addr:08x}'
            symbol_bytes = bin_data[cur_addr:]
            sym = Symbol(cur_addr, sym_name, '$d', bin_size - cur_addr, last_segment)
            total_inter += sym.size
            cur_addr += sym.size
        elif cur_addr == addrs[0]:
            sym = symbol_dict[cur_addr]
            sym_name = sanitize(sym.name)
            sym_size = sym.size
            next_addr = addrs[1] if len(addrs) > 1 else bin_size
            if cur_addr + sym_size > next_addr:
                sym_size = next_addr - cur_addr
            symbol_bytes = bin_data[sym.addr:sym.addr + sym_size]
            sym = Symbol(cur_addr, sym_name, sym.mode, sym_size, sym.segment)
            last_segment = sym.segment
            cur_addr += sym.size
            total_named += sym.size
            addrs.pop(0)
        elif cur_addr < addrs[0]:
            sym_name = f'{cur_addr:08x}'
            symbol_bytes = bin_data[cur_addr:addrs[0]]
            sym = Symbol(cur_addr, sym_name, "$d", addrs[0] - cur_addr, last_segment)
            cur_addr = addrs[0]
            total_inter += sym.size
        else:
            raise RuntimeError(
                f"cur_addr ({cur_addr:08x}) grew beyond next symbol ({addrs[0]:08x})!")

        o = ELF.from_bytes_single(symbol_bytes, sym)
        all_o.append(o)
        o_file = split_dir / f'{sanitize(sym.name)}.o'
        o.write(o_file)
        splat.append((sym.addr, o_file))

    total_bin_data = sum(len(o.data) for o in all_o)
    total_symbol_size = total_named + total_inter
    if total_bin_data != bin_size or bin_size != total_symbol_size:
        raise Exception(
            f"Split size mismatch! Expected {bin_size}, got {total_bin_data} and {total_symbol_size}")

    if progress:
        print(f"  [SPLIT] 100% ({len(splat)} objects)")
    return splat


def run_split(config: ProjectConfig, progress: bool = True):
    """Split all binaries in the project."""
    sym_dir = config.working_dir / 'symbols'
    for name in config.binaries:
        split_dir = config.split_dir / name
        split_dir.mkdir(parents=True, exist_ok=True)
        stamp = split_dir / '.split_stamp'
        csv_file = sym_dir / f'{name}.csv'
        if stamp.exists() and csv_file.exists():
            if stamp.stat().st_mtime >= csv_file.stat().st_mtime:
                if progress:
                    print(f"  {name}: up to date")
                continue
        print(f"Splitting {name}...")
        symbols = config.symbols.get(name, [])
        split_binary(config.binaries[name], split_dir, symbols, progress)
        stamp.write_bytes(b'')
    print("Split complete.")
