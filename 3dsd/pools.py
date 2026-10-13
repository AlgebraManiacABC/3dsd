"""Literal pools after functions, measured as data rather than code.

armcc ends a function's symbol at its last instruction and puts the
function's literal pool -- the constants and addresses it loads with
`ldr rX, [pc, #imm]` -- right after it, outside the symbol. objdiff has no
notion of ARM pools, so in the target those bytes fell into the gap before
the next symbol and became a `pad_` "function": counted in `total_code` and
`total_functions`, never paired, never compared. On New Leaf that was 21,913
of 60,190 functions and 1.27 MB of code, and a decompiled function with a
wrong constant in its pool still read 100%.

Pools are data, so they are measured as data: each one becomes an object
`<function>$pool` in a section of its own, `.pool:<function>`, on both sides
(datasplit.py does the base). A decompiled function's pool then pairs with
the compiled one and counts toward matched data when it is identical; the
pools of undecompiled functions go wherever undecompiled data goes.

Both sides find a pool the same way, so they agree on its extent: from the
end of the function to the end of the furthest word one of its pc-relative
loads reaches past that end, but never past the next symbol.
"""

import struct

#: Section-name prefix and symbol suffix for a function's trailing pool.
POOL_SEGMENT = '.pool'
POOL_SUFFIX = '$pool'


def pool_symbol(function: str) -> str:
    """The name the pool after `function` goes by, on both sides."""
    return function + POOL_SUFFIX


def pool_section(function: str) -> str:
    """The section the pool after `function` is given, on both sides."""
    return f'{POOL_SEGMENT}:{function}'


def _arm_load(word: int, off: int) -> tuple[int, int] | None:
    """`(address, size)` an ARM pc-relative load reads, or None."""
    if word >> 28 == 0xF:
        return None
    up = word & 0x00800000
    if word & 0x0F7F0000 == 0x051F0000:  # ldr rX, [pc, #±imm12]
        imm = word & 0xFFF
        return off + 8 + (imm if up else -imm), 4
    if word & 0x0F3F0E00 == 0x0D1F0A00:  # vldr sX/dX, [pc, #±imm8*4]
        imm = (word & 0xFF) * 4
        return off + 8 + (imm if up else -imm), 8 if word & 0x100 else 4
    if word & 0x0E5F00F0 == 0x014F00D0:  # ldrd rX, [pc, #±imm8]
        imm = ((word >> 4) & 0xF0) | (word & 0xF)
        return off + 8 + (imm if up else -imm), 8
    return None


def trailing_pool(code: bytes, start: int, end: int, thumb: bool, limit: int) -> int:
    """Where the literal pool after the function at `[start, end)` ends.

    `code` holds the function at those offsets and `limit` is where the next
    symbol begins. Returns `end` itself when the function loads nothing from
    beyond its own extent.
    """
    pool_end = end
    if thumb:
        for off in range(start, end - 1, 2):
            half = struct.unpack_from('<H', code, off)[0]
            if half & 0xF800 == 0x4800:  # ldr rX, [pc, #imm8*4]
                addr = ((off + 4) & ~3) + (half & 0xFF) * 4
                if end <= addr and addr + 4 <= limit:
                    pool_end = max(pool_end, addr + 4)
        return pool_end
    for off in range(start, end - 3, 4):
        load = _arm_load(struct.unpack_from('<I', code, off)[0], off)
        if load is not None:
            addr, size = load
            if end <= addr and addr + size <= limit:
                pool_end = max(pool_end, addr + size)
    return pool_end
