import subprocess
import tempfile
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


def cro_from_elf(linked_elf: Path, original_cro: Path, output: Path, objcopy: Path):
    """Flatten a linked ELF and splice it into a CRO in one step.

    objcopy only writes to a file, so the raw payload goes to the system
    temp directory and is discarded immediately — it never lands in out/.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        raw = Path(td) / 'linked.bin'
        result = subprocess.run(
            [str(objcopy), str(linked_elf), '-O', 'binary', str(raw)])
        if result.returncode != 0:
            raise RuntimeError(
                f"objcopy failed on {linked_elf} (exit {result.returncode})")
        recreate_cro(raw, original_cro, output)
