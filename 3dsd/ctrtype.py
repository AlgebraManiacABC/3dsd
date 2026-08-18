import hashlib
from enum import IntEnum
from typing import TypeVar, Generic
from typing_extensions import override

from .util import (
    BinaryReader, BinaryWriter, Writable, WritableStr, WritableBytes, RelocationType,
)


class CTRSectionType(IntEnum):
    TEXT = 0
    RODATA = 1
    DATA = 2
    BSS = 3


class OffSize:
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
    def __init__(self, off: int, obj: T | list[T]):
        self.off = off
        self.obj = obj

    def write(self, writer: BinaryWriter):
        ret = writer.tell()
        to_write = self.obj if isinstance(self.obj, list) else [self.obj]
        writer.seek(self.off)
        for obj in to_write:
            obj.write(writer)
        writer.seek(ret)

    def get_size(self, elem_size: int):
        if elem_size == 1 and self.obj and isinstance(self.obj[0], WritableStr):
            return sum(len(s) + 1 for s in self.obj)
        return len(self.obj) * elem_size

    def as_OffSize(self, elem_size: int = 1) -> OffSize:
        return OffSize(self.off, self.get_size(elem_size))


class CTRSectionInfo(OffSize):
    def __init__(self, addr: int, size: int, type: CTRSectionType):
        super().__init__(addr, size)
        self.type = type

    @classmethod
    def from_reader_with_type(cls, reader: BinaryReader, type: CTRSectionType) -> "CTRSectionInfo":
        addr = reader.read_u32()
        reader.read_u32()
        size = reader.read_u32()
        reader.read_u32()
        return cls(addr, size, type)

    @classmethod
    def from_cro_reader(cls, reader: BinaryReader) -> "CTRSectionInfo":
        addr = reader.read_u32()
        size = reader.read_u32()
        type = CTRSectionType(reader.read_u32())
        return cls(addr, size, type)

    @override
    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32(self.size)
        writer.write_u32(self.type.value)


class ExHeader:
    def __init__(self, text, rodata, data, bss):
        self.text: CTRSectionInfo = text
        self.rodata: CTRSectionInfo = rodata
        self.data: CTRSectionInfo = data
        self.bss: CTRSectionInfo = bss

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExHeader":
        reader.seek(0x10)
        text = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.TEXT)
        rodata = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.RODATA)
        data = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.DATA)
        bss = CTRSectionInfo(data.off + data.size, reader.read_u32(), CTRSectionType.BSS)
        return cls(text, rodata, data, bss)


class SegmentOffset:
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
    def __init__(self, seg_off: SegmentOffset, type: RelocationType, misc):
        self.seg_off = seg_off
        self.type = type
        self.misc = misc

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRORelocationEntry":
        seg_off = SegmentOffset.from_reader(reader)
        type = RelocationType(reader.read_u8())
        misc = reader.read_bytes(7)
        return cls(seg_off, type, misc)

    def write(self, writer: BinaryWriter):
        self.seg_off.write(writer)
        writer.write_u8(self.type.value)
        writer.write_bytes(self.misc)


class NamedImportTableEntry:
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
    def __init__(self, off: int, seg_off: SegmentOffset):
        self.off = off
        self.seg_off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "UnknownRelocationInfo":
        return cls(reader.read_u32(), SegmentOffset.from_reader(reader))

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        self.seg_off.write(writer)


class CRO:
    def __init__(self, misc_info, cro_size, bss_size, misc_info_2,
                 nnroCO, OnLoad, OnExit, OnUnresolved,
                 text, data, module_name, segment_table,
                 named_export_table, indexed_export_table, export_strings,
                 export_trie, import_module_table, import_relocations,
                 named_import_table, indexed_import_table, anon_import_table,
                 import_strings, unk_reloc_base, internal_relocs, unk_relocs):
        self.misc_info = misc_info
        self.cro_size = cro_size
        self.bss_size = bss_size
        self.misc_info_2 = misc_info_2
        self.nnroCO = nnroCO
        self.OnLoad = OnLoad
        self.OnExit = OnExit
        self.OnUnresolved = OnUnresolved
        self.text = text
        self.data = data
        self.module_name = module_name
        self.segment_table = segment_table
        self.named_export_table = named_export_table
        self.indexed_export_table = indexed_export_table
        self.export_strings = export_strings
        self.export_trie = export_trie
        self.import_module_table = import_module_table
        self.import_relocations = import_relocations
        self.named_import_table = named_import_table
        self.indexed_import_table = indexed_import_table
        self.anon_import_table = anon_import_table
        self.import_strings = import_strings
        self.unk_reloc_base = unk_reloc_base
        self.internal_relocs = internal_relocs
        self.unk_relocs = unk_relocs

    def get_text_bytes(self) -> bytes:
        return self.text.obj

    def get_data_bytes(self) -> bytes:
        return self.data.obj

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRO":
        reader.seek(0x80)
        magic = reader.read_bytes(4)
        if magic != b'CRO0':
            raise Exception("Invalid CRO0 format!")
        misc_info = reader.read_bytes(0xC)
        cro_size = reader.read_u32()
        bss_size = reader.read_u32()
        misc_info_2 = reader.read_bytes(0x8)
        nnroCO = SegmentOffset.from_reader(reader)
        OnLoad = SegmentOffset.from_reader(reader)
        OnExit = SegmentOffset.from_reader(reader)
        OnUnresolved = SegmentOffset.from_reader(reader)
        text_info = OffSize.from_reader(reader)
        data_info = OffSize.from_reader(reader)
        module_name_info = OffSize.from_reader(reader)
        segment_table_info = OffSize.from_reader(reader)
        named_export_table_info = OffSize.from_reader(reader)
        indexed_export_table_info = OffSize.from_reader(reader)
        export_strings_info = OffSize.from_reader(reader)
        export_trie_info = OffSize.from_reader(reader)
        import_module_table_info = OffSize.from_reader(reader)
        import_relocations_info = OffSize.from_reader(reader)
        named_import_table_info = OffSize.from_reader(reader)
        indexed_import_table_info = OffSize.from_reader(reader)
        anon_import_table_info = OffSize.from_reader(reader)
        import_strings_info = OffSize.from_reader(reader)
        unk_reloc_base_info = OffSize.from_reader(reader)
        internal_reloc_info = OffSize.from_reader(reader)
        unk_reloc_info = OffSize.from_reader(reader)

        def read_list(info, factory):
            reader.seek(info.off)
            return OffObject(info.off, [factory(reader) for _ in range(info.size)])

        def read_strings(info):
            reader.seek(info.off)
            result, remaining = [], info.size
            while remaining > 0:
                s = reader.read_str()
                remaining -= len(s) + 1
                result.append(WritableStr(s))
            return OffObject(info.off, result)

        reader.seek(text_info.off)
        text = OffObject(text_info.off, WritableBytes(reader.read_bytes(text_info.size)))
        reader.seek(data_info.off)
        data = OffObject(data_info.off, WritableBytes(reader.read_bytes(data_info.size)))
        reader.seek(module_name_info.off)
        module_name = OffObject(module_name_info.off,
                                WritableStr(reader.read_bytes(module_name_info.size).decode('utf-8')))
        segment_table = read_list(segment_table_info, CTRSectionInfo.from_cro_reader)
        named_export_table = read_list(named_export_table_info, NamedExportTableEntry.from_reader)
        reader.seek(indexed_export_table_info.off)
        indexed_export_table = OffObject(indexed_export_table_info.off,
                                         [SegmentOffset.from_reader(reader) for _ in range(indexed_export_table_info.size)])
        export_strings = read_strings(export_strings_info)
        export_trie = read_list(export_trie_info, ExportTrieEntry.from_reader)
        import_module_table = read_list(import_module_table_info, ImportModuleTableEntry.from_reader)
        import_relocations = read_list(import_relocations_info, CRORelocationEntry.from_reader)
        named_import_table = read_list(named_import_table_info, NamedImportTableEntry.from_reader)
        indexed_import_table = read_list(indexed_import_table_info, IndexedImportTableEntry.from_reader)
        anon_import_table = read_list(anon_import_table_info, AnonImportTableEntry.from_reader)
        import_strings = read_strings(import_strings_info)
        unk_reloc_base = read_list(unk_reloc_base_info, UnknownRelocationInfo.from_reader)
        internal_relocs = read_list(internal_reloc_info, CRORelocationEntry.from_reader)
        unk_relocs = read_list(unk_reloc_info, CRORelocationEntry.from_reader)

        return cls(misc_info, cro_size, bss_size, misc_info_2,
                   nnroCO, OnLoad, OnExit, OnUnresolved, text, data,
                   module_name, segment_table, named_export_table, indexed_export_table,
                   export_strings, export_trie, import_module_table, import_relocations,
                   named_import_table, indexed_import_table, anon_import_table,
                   import_strings, unk_reloc_base, internal_relocs, unk_relocs)

    def write(self, writer: BinaryWriter):
        writer.seek(0x80)
        writer.write_bytes(b'CRO0')
        writer.write_bytes(self.misc_info)
        writer.write_u32(self.cro_size)
        writer.write_u32(self.bss_size)
        writer.write_bytes(self.misc_info_2)
        for seg_off in [self.nnroCO, self.OnLoad, self.OnExit, self.OnUnresolved]:
            seg_off.write(writer)
        for tbl in [self.text, self.data, self.module_name, self.segment_table,
                     self.named_export_table, self.indexed_export_table, self.export_strings,
                     self.export_trie, self.import_module_table, self.import_relocations,
                     self.named_import_table, self.indexed_import_table, self.anon_import_table,
                     self.import_strings, self.unk_reloc_base, self.internal_relocs, self.unk_relocs]:
            tbl.as_OffSize().write(writer)
        for tbl in [self.text, self.data, self.module_name, self.segment_table,
                     self.named_export_table, self.indexed_export_table, self.export_strings,
                     self.export_trie, self.import_module_table, self.import_relocations,
                     self.named_import_table, self.indexed_import_table, self.anon_import_table,
                     self.import_strings, self.unk_reloc_base, self.internal_relocs, self.unk_relocs]:
            tbl.write(writer)

        cur_size = len(writer.getvalue())
        writer.seek(cur_size)
        writer.write_bytes(b'\xCC' * (self.cro_size - cur_size))

        writer.seek(0)
        for bounds in [(0x80, self.text.off),
                       (self.text.off, self.module_name.off),
                       (self.module_name.off, self.data.off),
                       (self.data.off, self.data.off + self.data.as_OffSize().size)]:
            sha256 = hashlib.sha256(writer.getvalue()[bounds[0]:bounds[1]]).digest()
            writer.write_bytes(sha256)

    @classmethod
    def from_cro(cls, cro: "CRO", data: bytes) -> "CRO":
        data = bytearray(data)[:len(cro.text.obj)]
        text_section = OffObject(cro.text.off, WritableBytes(data))
        return cls(cro.misc_info, cro.cro_size, cro.bss_size, cro.misc_info_2,
                   cro.nnroCO, cro.OnLoad, cro.OnExit, cro.OnUnresolved,
                   text_section, cro.data, cro.module_name, cro.segment_table,
                   cro.named_export_table, cro.indexed_export_table,
                   cro.export_strings, cro.export_trie, cro.import_module_table,
                   cro.import_relocations, cro.named_import_table,
                   cro.indexed_import_table, cro.anon_import_table,
                   cro.import_strings, cro.unk_reloc_base,
                   cro.internal_relocs, cro.unk_relocs)


class CTRBinary:
    def __init__(self, name: str, binary: bytes | CRO, exh: ExHeader = None):
        self.name = name
        self.binary = binary
        if isinstance(binary, CRO):
            self.data = self.binary.get_text_bytes() + self.binary.get_data_bytes()
            self.base_addr = self.binary.text.off
            self.text_size = len(self.binary.text.obj)
        else:
            self.data = self.binary
            self.base_addr = 0x100000
            self.text_size = exh.text.size if exh else len(self.data)
