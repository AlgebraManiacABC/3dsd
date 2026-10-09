"""Readers and writers for 3DS container formats: the ExHeader and CRO modules."""

import dataclasses
import hashlib
from enum import IntEnum
from typing import Generic, TypeVar

try:
    from typing import override  # Python 3.12+
except ImportError:
    def override(func):  # static-checking decorator only; no-op at runtime
        return func

from .util import (
    BinaryReader,
    BinaryWriter,
    PipelineError,
    RelocationType,
    Writable,
    WritableBytes,
    WritableStr,
)


class CTRSectionType(IntEnum):
    """Segment index used by the ExHeader and CRO segment tables."""
    TEXT = 0
    RODATA = 1
    DATA = 2
    BSS = 3


class OffSize:
    """An (offset, size) pair, the unit every CRO header table is described by."""

    def __init__(self, off: int, size: int):
        self.off = off
        self.size = size

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "OffSize":
        return cls(reader.read_u32(), reader.read_u32())

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32(self.size)


T = TypeVar("T", bound=Writable)


class OffObject(Generic[T]):
    """A value, or list of values, that lives at a fixed offset in the file."""

    def __init__(self, off: int, obj: T | list[T]):
        self.off = off
        self.obj = obj

    def write(self, writer: BinaryWriter):
        """Write the value at its own offset, leaving the writer where it was."""
        ret = writer.tell()
        to_write = self.obj if isinstance(self.obj, list) else [self.obj]
        writer.seek(self.off)
        for obj in to_write:
            obj.write(writer)
        writer.seek(ret)

    def get_size(self, elem_size: int):
        """Size in elements, or in bytes for a list of strings."""
        if elem_size == 1 and self.obj and isinstance(self.obj[0], WritableStr):
            return sum(len(s) + 1 for s in self.obj)
        return len(self.obj) * elem_size

    def as_off_size(self, elem_size: int = 1) -> OffSize:
        return OffSize(self.off, self.get_size(elem_size))


class CTRSectionInfo(OffSize):
    """One segment: its address, size and which kind of segment it is.

    `pages` is the number of 4 KB pages an ExHeader code set occupies; the
    next code set starts after them. Zero for CRO segments, which have none.
    """

    def __init__(self, addr: int, size: int, sec_type: CTRSectionType, pages: int = 0):
        super().__init__(addr, size)
        self.type = sec_type
        self.pages = pages

    @classmethod
    def from_exheader(cls, reader: BinaryReader, off: int,
                      sec_type: CTRSectionType) -> "CTRSectionInfo":
        """Read an ExHeader code-set entry: address, page count, byte size."""
        reader.seek(off)
        addr = reader.read_u32()
        pages = reader.read_u32()
        size = reader.read_u32()
        return cls(addr, size, sec_type, pages)

    @property
    def page_end(self) -> int:
        """First address after the pages this code set occupies."""
        return self.off + self.pages * 0x1000

    @classmethod
    def from_cro_reader(cls, reader: BinaryReader) -> "CTRSectionInfo":
        """Read a CRO segment table entry (offset, size, type)."""
        addr = reader.read_u32()
        size = reader.read_u32()
        sec_type = CTRSectionType(reader.read_u32())
        return cls(addr, size, sec_type)

    @override
    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32(self.size)
        writer.write_u32(self.type.value)


class ExHeader:
    """The code-set layout from an extended header (exheader.bin).

    Layout per https://www.3dbrew.org/wiki/NCCH/Extended_Header: three
    12-byte code sets at 0x10 (text), 0x20 (read-only) and 0x30 (data), each
    followed by an unrelated word (stack size, reserved, BSS size).
    """

    def __init__(self, text, rodata, data, bss):
        self.text: CTRSectionInfo = text
        self.rodata: CTRSectionInfo = rodata
        self.data: CTRSectionInfo = data
        self.bss: CTRSectionInfo = bss

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExHeader":
        text = CTRSectionInfo.from_exheader(reader, 0x10, CTRSectionType.TEXT)
        rodata = CTRSectionInfo.from_exheader(reader, 0x20, CTRSectionType.RODATA)
        data = CTRSectionInfo.from_exheader(reader, 0x30, CTRSectionType.DATA)
        reader.seek(0x3C)
        # BSS has no code set of its own: it starts right after the data bytes.
        bss = CTRSectionInfo(data.off + data.size, reader.read_u32(), CTRSectionType.BSS)
        return cls(text, rodata, data, bss)

    def segment_of(self, addr: int) -> str | None:
        """The segment an absolute address really lies in, or None if outside.

        The page padding after .text and .rodata belongs to them; .data ends at
        its last byte, where .bss begins.
        """
        if self.text.off <= addr < self.text.page_end:
            return '.text'
        if self.rodata.off <= addr < self.rodata.page_end:
            return '.rodata'
        if self.data.off <= addr < self.bss.off:
            return '.data'
        if self.bss.off <= addr < self.bss.off + self.bss.size:
            return '.bss'
        return None


class SegmentOffset:
    """A CRO segment-relative address: 4-bit segment index, 28-bit offset."""

    def __init__(self, seg_idx: int, seg_off: int):
        self.index = seg_idx
        self.off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SegmentOffset":
        tmp = reader.read_u32()
        return cls(tmp & 0x0F, tmp >> 4)

    def write(self, writer: BinaryWriter):
        writer.write_u32((self.off << 4) | self.index)


class NamedExportTableEntry:
    """A CRO export by name."""

    def __init__(self, name: OffObject, seg_off: SegmentOffset):
        self.name = name
        self.seg_off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "NamedExportTableEntry":
        name_off = reader.read_u32()
        ret = reader.tell()
        reader.seek(name_off)
        name = reader.read_str()
        reader.seek(ret)
        seg_off = SegmentOffset.from_reader(reader)
        return cls(OffObject(name_off, name), seg_off)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name.off)
        self.seg_off.write(writer)


class ExportTrieEntry:
    """A node of the CRO's export-name lookup trie."""

    def __init__(self, flags: int, left: int, right: int, index: int):
        self.flags = flags
        self.left = left
        self.right = right
        self.index = index

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExportTrieEntry":
        return cls(reader.read_u16(), reader.read_u16(), reader.read_u16(), reader.read_u16())

    def write(self, writer: BinaryWriter):
        writer.write_u16(self.flags)
        writer.write_u16(self.left)
        writer.write_u16(self.right)
        writer.write_u16(self.index)


class ImportModuleTableEntry:
    """A module this CRO imports from, with its indexed and anonymous imports."""

    def __init__(self, name: OffObject, indexed: OffSize, anon: OffSize):
        self.name = name
        self.indexed = indexed
        self.anon = anon

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ImportModuleTableEntry":
        name_off = reader.read_u32()
        indexed = OffSize.from_reader(reader)
        anon = OffSize.from_reader(reader)
        ret = reader.tell()
        reader.seek(name_off)
        name = reader.read_str()
        reader.seek(ret)
        return cls(OffObject(name_off, name), indexed, anon)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name.off)
        self.indexed.write(writer)
        self.anon.write(writer)


class CRORelocationEntry:
    """A CRO relocation: target, type and seven bytes of type-specific data."""

    def __init__(self, seg_off: SegmentOffset, rel_type: RelocationType, misc):
        self.seg_off = seg_off
        self.type = rel_type
        self.misc = misc

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRORelocationEntry":
        seg_off = SegmentOffset.from_reader(reader)
        rel_type = RelocationType(reader.read_u8())
        misc = reader.read_bytes(7)
        return cls(seg_off, rel_type, misc)

    def write(self, writer: BinaryWriter):
        self.seg_off.write(writer)
        writer.write_u8(self.type.value)
        writer.write_bytes(self.misc)


class NamedImportTableEntry:
    """A CRO import by name."""

    def __init__(self, name: OffObject, off: int):
        self.name = name
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "NamedImportTableEntry":
        name_off = reader.read_u32()
        off = reader.read_u32()
        ret = reader.tell()
        reader.seek(name_off)
        name = OffObject(name_off, reader.read_str())
        reader.seek(ret)
        return cls(name, off)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name.off)
        writer.write_u32(self.off)


class IndexedImportTableEntry:
    """A CRO import by export index."""

    def __init__(self, index: int, off: int):
        self.index = index
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "IndexedImportTableEntry":
        return cls(reader.read_u32(), reader.read_u32())

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.index)
        writer.write_u32(self.off)


class AnonImportTableEntry:
    """A CRO import by segment offset."""

    def __init__(self, seg_off: SegmentOffset, off: int):
        self.seg_off = seg_off
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "AnonImportTableEntry":
        return cls(SegmentOffset.from_reader(reader), reader.read_u32())

    def write(self, writer: BinaryWriter):
        self.seg_off.write(writer)
        writer.write_u32(self.off)


class UnknownRelocationInfo:
    """An entry of the CRO table whose purpose is not yet understood."""

    def __init__(self, off: int, seg_off: SegmentOffset):
        self.off = off
        self.seg_off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "UnknownRelocationInfo":
        return cls(reader.read_u32(), SegmentOffset.from_reader(reader))

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        self.seg_off.write(writer)


# How each CRO header table is read, in header order. A factory reads one list
# element; the three string kinds are handled by `_read_table`.
_BYTES, _STR, _STRINGS = 'bytes', 'str', 'strings'
_CRO_TABLES = {
    'text': _BYTES,
    'data': _BYTES,
    'module_name': _STR,
    'segment_table': CTRSectionInfo.from_cro_reader,
    'named_export_table': NamedExportTableEntry.from_reader,
    'indexed_export_table': SegmentOffset.from_reader,
    'export_strings': _STRINGS,
    'export_trie': ExportTrieEntry.from_reader,
    'import_module_table': ImportModuleTableEntry.from_reader,
    'import_relocations': CRORelocationEntry.from_reader,
    'named_import_table': NamedImportTableEntry.from_reader,
    'indexed_import_table': IndexedImportTableEntry.from_reader,
    'anon_import_table': AnonImportTableEntry.from_reader,
    'import_strings': _STRINGS,
    'unk_reloc_base': UnknownRelocationInfo.from_reader,
    'internal_relocs': CRORelocationEntry.from_reader,
    'unk_relocs': CRORelocationEntry.from_reader,
}


def _read_table(reader: BinaryReader, info: OffSize, kind) -> OffObject:
    """Read one header table described by `info`."""
    reader.seek(info.off)
    if kind == _BYTES:
        return OffObject(info.off, WritableBytes(reader.read_bytes(info.size)))
    if kind == _STR:
        return OffObject(info.off, WritableStr(reader.read_bytes(info.size).decode('utf-8')))
    if kind == _STRINGS:
        result, remaining = [], info.size
        while remaining > 0:
            s = reader.read_str()
            remaining -= len(s) + 1
            result.append(WritableStr(s))
        return OffObject(info.off, result)
    return OffObject(info.off, [kind(reader) for _ in range(info.size)])


@dataclasses.dataclass
class CRO:  # pylint: disable=too-many-instance-attributes
    """A CRO module, parsed far enough to swap its code and write it back.

    Field order is the on-disk header order; the tables after the four entry
    points are exactly the keys of `_CRO_TABLES`.
    """
    misc_info: bytes
    cro_size: int
    bss_size: int
    misc_info_2: bytes
    nnro_control_object: SegmentOffset
    on_load: SegmentOffset
    on_exit: SegmentOffset
    on_unresolved: SegmentOffset
    text: OffObject
    data: OffObject
    module_name: OffObject
    segment_table: OffObject
    named_export_table: OffObject
    indexed_export_table: OffObject
    export_strings: OffObject
    export_trie: OffObject
    import_module_table: OffObject
    import_relocations: OffObject
    named_import_table: OffObject
    indexed_import_table: OffObject
    anon_import_table: OffObject
    import_strings: OffObject
    unk_reloc_base: OffObject
    internal_relocs: OffObject
    unk_relocs: OffObject

    def get_text_bytes(self) -> bytes:
        return self.text.obj

    def get_data_bytes(self) -> bytes:
        return self.data.obj

    def _tables(self) -> list[OffObject]:
        return [getattr(self, name) for name in _CRO_TABLES]

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRO":
        """Parse a CRO module from the start of `reader`."""
        reader.seek(0x80)
        if reader.read_bytes(4) != b'CRO0':
            raise PipelineError(f"{reader.name}: not a CRO module (no CRO0 magic)")
        header = {
            'misc_info': reader.read_bytes(0xC),
            'cro_size': reader.read_u32(),
            'bss_size': reader.read_u32(),
            'misc_info_2': reader.read_bytes(0x8),
            'nnro_control_object': SegmentOffset.from_reader(reader),
            'on_load': SegmentOffset.from_reader(reader),
            'on_exit': SegmentOffset.from_reader(reader),
            'on_unresolved': SegmentOffset.from_reader(reader),
        }
        infos = {name: OffSize.from_reader(reader) for name in _CRO_TABLES}
        tables = {name: _read_table(reader, infos[name], kind)
                  for name, kind in _CRO_TABLES.items()}
        return cls(**header, **tables)

    def write(self, writer: BinaryWriter):
        """Serialise the module, padding to `cro_size` and rehashing the header."""
        writer.seek(0x80)
        writer.write_bytes(b'CRO0')
        writer.write_bytes(self.misc_info)
        writer.write_u32(self.cro_size)
        writer.write_u32(self.bss_size)
        writer.write_bytes(self.misc_info_2)
        for seg_off in [self.nnro_control_object, self.on_load, self.on_exit,
                        self.on_unresolved]:
            seg_off.write(writer)
        tables = self._tables()
        for tbl in tables:
            tbl.as_off_size().write(writer)
        for tbl in tables:
            tbl.write(writer)

        cur_size = len(writer.getvalue())
        writer.seek(cur_size)
        writer.write_bytes(b'\xCC' * (self.cro_size - cur_size))

        writer.seek(0)
        for start, end in [(0x80, self.text.off),
                           (self.text.off, self.module_name.off),
                           (self.module_name.off, self.data.off),
                           (self.data.off, self.data.off + self.data.as_off_size().size)]:
            writer.write_bytes(hashlib.sha256(writer.getvalue()[start:end]).digest())

    @classmethod
    def from_cro(cls, cro: "CRO", data: bytes) -> "CRO":
        """A copy of `cro` with its code replaced by `data`, trimmed to fit."""
        data = bytearray(data)[:len(cro.text.obj)]
        return dataclasses.replace(cro, text=OffObject(cro.text.off, WritableBytes(data)))


class CTRBinary:
    """An original binary -- code.bin or a CRO -- as the pipeline sees it."""

    def __init__(self, name: str, binary: bytes | CRO, exh: ExHeader | None = None):
        self.name = name
        self.binary = binary
        self.exheader = exh
        if isinstance(binary, CRO):
            self.data = self.binary.get_text_bytes() + self.binary.get_data_bytes()
            self.base_addr = self.binary.text.off
            self.text_size = len(self.binary.text.obj)
        else:
            self.data = self.binary
            self.base_addr = 0x100000
            self.text_size = exh.text.size if exh else len(self.data)
