"""Memory zeroing utilities for secure deletion."""

import ctypes
import ctypes.util
from typing import Union

try:
    from secure_delete import secure_delete
except ImportError:
    secure_delete = None


def secure_zero(data: Union[bytearray, bytes]) -> None:
    """
    Securely zero memory containing sensitive data.

    Attempts to overwrite memory with zeros to prevent sensitive data
    from remaining in memory after use. This is a best-effort operation
    due to Python's memory management limitations.

    For bytearray (mutable): Attempts to zero in-place using secure
    deletion methods or ctypes memset.

    For bytes (immutable): Cannot zero in-place. The caller should
    ensure bytes objects containing secrets are not kept in memory
    longer than necessary. Python's garbage collector will eventually
    reclaim the memory, but this cannot be guaranteed to be immediate.

    Args:
        data: The data to zero. If bytearray, will be zeroed in-place.
            If bytes, this function documents the limitation but cannot
            actually zero immutable objects.

    Note:
        Python's memory management makes it difficult to guarantee that
        memory is immediately zeroed. This function provides best-effort
        zeroing for mutable bytearray objects. For immutable bytes objects,
        the caller should avoid keeping sensitive data in memory longer
        than necessary.

    Example:
        >>> sensitive = bytearray(b"secret data")
        >>> secure_zero(sensitive)
        >>> all(b == 0 for b in sensitive)
        True
    """
    if isinstance(data, bytearray):
        # Use ctypes to call C memset for in-place zeroing
        try:
            # Get the C library (works on Unix/Linux/Mac)
            # On Windows, try msvcrt
            try:
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
            except (OSError, AttributeError):
                # On Windows, use msvcrt
                libc = ctypes.CDLL("msvcrt")
            
            # Get memset function
            memset = libc.memset
            memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            memset.restype = ctypes.c_void_p

            # Zero the memory
            memset(
                ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data)
            )
        except (AttributeError, TypeError, ValueError, OSError):
            # If ctypes fails, use Python assignment
            # This overwrites the bytearray contents with zeros
            data[:] = b"\x00" * len(data)
    elif isinstance(data, bytes):
        # Cannot zero immutable bytes in-place
        # Document the limitation - caller should avoid keeping bytes secrets
        pass
    else:
        raise TypeError(f"Expected bytearray or bytes, got {type(data).__name__}")

