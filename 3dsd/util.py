import re
import struct
from enum import IntEnum
from io import BytesIO
from pathlib import Path
from typing import Protocol


class BinaryReader:
    def __init__(self, name: str, data: bytes):
        self._stream = BytesIO(data)
        self.name = name

    @classmethod
    def from_path(cls, path: Path) -> "BinaryReader":
        return cls(path.name, path.read_bytes())

    def seek(self, offset: int):
        self._stream.seek(offset)

    def tell(self) -> int:
        return self._stream.tell()

    def read_bytes(self, size: int) -> bytes:
        return self._stream.read(size)

    def read_u8(self) -> int:
        return struct.unpack("<B", self._stream.read(1))[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self._stream.read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self._stream.read(4))[0]

    def read_s32(self) -> int:
        return struct.unpack("<i", self._stream.read(4))[0]

    def read_str(self) -> str:
        buf = BytesIO()
        while True:
            b = self._stream.read(1)
            if not b or b == b'\x00':
                break
            buf.write(b)
        return buf.getvalue().decode('utf-8')


class BinaryWriter:
    def __init__(self):
        self._stream = BytesIO()

    def seek(self, offset: int):
        self._stream.seek(offset)

    def tell(self) -> int:
        return self._stream.tell()

    def write_bytes(self, data: bytes):
        self._stream.write(data)

    def write_u8(self, value: int):
        self._stream.write(struct.pack("<B", value))

    def write_u16(self, value: int):
        self._stream.write(struct.pack("<H", value))

    def write_u32(self, value: int):
        self._stream.write(struct.pack("<I", value))

    def write_s32(self, value: int):
        self._stream.write(struct.pack("<i", value))

    def write_str(self, s: str):
        self._stream.write(s.encode('utf-8') + b'\x00')

    def flush(self, path: Path):
        path.write_bytes(self._stream.getvalue())

    def getvalue(self) -> bytes:
        return self._stream.getvalue()


class Writable(Protocol):
    def write(self, writer: BinaryWriter) -> None: ...


class WritableStr(str):
    def write(self, writer: BinaryWriter) -> None:
        writer.write_str(self)


class WritableBytes(bytes):
    def write(self, writer: BinaryWriter) -> None:
        writer.write_bytes(self)


class Symbol:
    def __init__(self, addr: int, name: str, mode: str, size: int, segment: str):
        self.addr = addr
        self.name = name
        self.mode = mode
        self.size = size
        self.segment = segment


class RelocationType(IntEnum):
    R_ARM_NONE = 0
    R_ARM_ABS32 = 2
    R_ARM_REL32 = 3
    R_ARM_THM_PC22 = 10
    R_ARM_CALL = 28
    R_ARM_JUMP24 = 29
    R_ARM_V4BX = 40
    R_ARM_TARGET1 = 38
    R_ARM_PREL31 = 42

    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'R_ARM_UNKNOWN_{value}'
        obj._value_ = value
        return obj


class RelocationEntry:
    def __init__(self, off: int, symbol_index: int, type: RelocationType):
        self.off = off
        self.symbol_index = symbol_index
        self.type = type

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "RelocationEntry":
        off = reader.read_u32()
        tmp = reader.read_u32()
        return cls(off, tmp >> 8, RelocationType(tmp & 0xFF))

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32((self.symbol_index << 8) | (self.type & 0xFF))


class Bitmask:
    def __init__(self, length: int):
        self.mask = bytearray(b'\xFF' * length)

    def add_relocation(self, rel_entry: RelocationEntry):
        match rel_entry.type:
            case RelocationType.R_ARM_NONE:
                pass  # marker reloc (e.g. armcc library references), no bytes affected
            case RelocationType.R_ARM_CALL | RelocationType.R_ARM_JUMP24:
                self.mask[rel_entry.off: rel_entry.off + 3] = b'\x00' * 3
            case RelocationType.R_ARM_THM_PC22:
                self.mask[rel_entry.off: rel_entry.off + 4] = b'\x00' * 4
            case RelocationType.R_ARM_ABS32 | RelocationType.R_ARM_REL32 | RelocationType.R_ARM_TARGET1 | RelocationType.R_ARM_PREL31:
                self.mask[rel_entry.off: rel_entry.off + 4] = b'\x00' * 4
            case _:
                self.mask[rel_entry.off: rel_entry.off + 4] = b'\x00' * 4

    def extend(self, mask: "Bitmask"):
        self.mask.extend(mask.mask)

    def copy(self) -> "Bitmask":
        cpy = Bitmask(0)
        cpy.mask = self.mask.copy()
        return cpy


def get_name(data: bytes, off: int) -> str:
    end = data.index(b'\x00', off)
    return data[off:end].decode('utf-8')


def pad_to_4(writer: BinaryWriter):
    while writer.tell() % 4 != 0:
        writer.write_u8(0)


def sanitize(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*`()\']', '_', name)
