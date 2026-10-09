"""Shared primitives: binary I/O, symbols, relocations and small helpers."""

import re
import struct
from enum import IntEnum
from io import BytesIO
from pathlib import Path
from typing import Protocol


class PipelineError(Exception):
    """A problem with the project or its inputs, reported without a traceback.

    Raised for anything the user fixes by editing their project -- a missing
    directory, a bad cc.yaml entry, a compiler that reports the wrong version
    -- as opposed to a bug in the pipeline itself.
    """


class BinaryReader:
    """Little-endian reader over an in-memory byte string."""

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
    """Little-endian writer into an in-memory buffer; seeking past the end
    zero-fills."""

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
    """Anything that can serialise itself into a BinaryWriter."""

    def write(self, writer: BinaryWriter) -> None:
        """Serialise into `writer` at its current position."""


class WritableStr(str):
    """A str that writes itself NUL-terminated."""

    def write(self, writer: BinaryWriter) -> None:
        """Write the string and its terminator."""
        writer.write_str(self)


class WritableBytes(bytes):
    """A bytes object that writes itself verbatim."""

    def write(self, writer: BinaryWriter) -> None:
        """Write the bytes as they are."""
        writer.write_bytes(self)


class Symbol:
    """One row of a symbol CSV. `addr` is made relative to the binary's base
    address once the binary is known."""

    def __init__(self, addr: int, name: str, mode: str, size: int, segment: str,
                 namespace: str = ''):
        self.addr = addr
        self.name = name
        self.mode = mode
        self.size = size
        self.segment = segment
        self.namespace = namespace

    @property
    def is_stdlib(self) -> bool:
        """True for anything in the C++ `std` namespace.

        These come out of the toolchain's `.a` files rather than the game's
        own source, so they are excluded from the objdiff target: nobody is
        going to decompile them, and counting them only deflates the
        completion percentage. The bytes still exist in the split, so the
        relinked binary stays byte-perfect either way.
        """
        return self.namespace == 'std' or self.namespace.startswith('std::')


class RelocationType(IntEnum):
    """ARM ELF relocation types; unlisted values become R_ARM_UNKNOWN_<n>."""
    R_ARM_NONE = 0
    R_ARM_ABS32 = 2
    R_ARM_REL32 = 3
    R_ARM_THM_PC22 = 10
    R_ARM_CALL = 28
    R_ARM_JUMP24 = 29
    R_ARM_TARGET1 = 38
    R_ARM_V4BX = 40
    R_ARM_PREL31 = 42

    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'R_ARM_UNKNOWN_{value}'
        obj._value_ = value
        return obj


def get_name(data: bytes, off: int) -> str:
    """The NUL-terminated string starting at `off` in a string table."""
    end = data.index(b'\x00', off)
    return data[off:end].decode('utf-8')


def pad_to_4(writer: BinaryWriter):
    """Zero-pad the writer up to the next 4-byte boundary."""
    while writer.tell() % 4 != 0:
        writer.write_u8(0)


def sanitize(name: str) -> str:
    """Make a symbol name safe to use as a file name on every platform."""
    return re.sub(r'[<>:"/\\|?*`()\']', '_', name)


def posix(p: Path | str) -> str:
    """A path with forward slashes, as build.ninja and objdiff.json want."""
    return str(p).replace('\\', '/')
