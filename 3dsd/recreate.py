import sys
from pathlib import Path

from .ctrtype import CRO, BinaryWriter
from .util import BinaryReader


def recreate_cro(linked_bin: Path, original_cro: Path, output: Path):
    """Replace the text section in a CRO with the linked binary data."""
    cro = CRO.from_reader(BinaryReader.from_path(original_cro))
    new_text = linked_bin.read_bytes()
    rebuilt = CRO.from_cro(cro, new_text)
    writer = BinaryWriter()
    rebuilt.write(writer)
    writer.flush(output)


def run_recreate_cro(argv: list[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="3dsd recreate-cro")
    parser.add_argument("--linked", required=True, help="Linked binary (objcopy output)")
    parser.add_argument("--original", required=True, help="Original .cro file")
    parser.add_argument("--output", required=True, help="Output .cro path")
    args = parser.parse_args(argv)
    recreate_cro(Path(args.linked), Path(args.original), Path(args.output))
    return 0
