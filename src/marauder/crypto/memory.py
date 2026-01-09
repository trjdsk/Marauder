"""Memory zeroing utilities for secure deletion."""

import ctypes
import ctypes.util
from typing import Union

try:
    from secure_delete import secure_delete
except ImportError:
    secure_delete = None


def secure_zero(data: Union[bytearray, bytes]) -> None:
    """Zero memory containing sensitive data. Best-effort for bytearray, no-op for bytes."""
    if isinstance(data, bytearray):
        try:
            try:
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
            except (OSError, AttributeError):
                libc = ctypes.CDLL("msvcrt")
            
            memset = libc.memset
            memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            memset.restype = ctypes.c_void_p

            memset(
                ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data)
            )
        except (AttributeError, TypeError, ValueError, OSError):
            data[:] = b"\x00" * len(data)
    elif isinstance(data, bytes):
        pass
    else:
        raise TypeError(f"Expected bytearray or bytes, got {type(data).__name__}")

