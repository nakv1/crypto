from __future__ import annotations

import ctypes
from contextlib import contextmanager
from typing import Iterator, Optional


def secure_zero_bytearray(buf: bytearray) -> None:
    if not isinstance(buf, bytearray):
        raise TypeError("buf должен быть bytearray")
    if len(buf) == 0:
        return

    ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(ctypes.addressof(ptr), 0, len(buf))


@contextmanager
def secure_buffer(initial: Optional[bytes] = None) -> Iterator[bytearray]:
    buf = bytearray(initial or b"")
    try:
        yield buf
    finally:
        secure_zero_bytearray(buf)
