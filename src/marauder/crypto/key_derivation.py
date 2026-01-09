"""Key derivation using Argon2id."""

from argon2 import Type
from argon2.low_level import hash_secret_raw
from argon2.exceptions import HashingError


# OWASP recommended parameters for Argon2id
# Memory cost: 64 MB (65536 KB)
# Time cost: 3 iterations
# Parallelism: 4 lanes
ARGON2_MEMORY_COST = 65536  # 64 MB in KB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
KEY_LENGTH = 32  # 32 bytes = 256 bits for AES-256
MIN_SALT_LENGTH = 16  # Minimum recommended salt length


def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from a password using Argon2id.

    Uses Argon2id with OWASP-recommended parameters to derive a 32-byte
    (256-bit) key suitable for AES-256 encryption. The same password and
    salt will always produce the same key.

    Args:
        password: The password as bytes. Must not be empty.
        salt: The salt as bytes. Must be at least 16 bytes (32 bytes recommended).

    Returns:
        A 32-byte key derived from the password and salt.

    Raises:
        ValueError: If password is empty, salt is too short, or other invalid input.
        HashingError: If Argon2 hashing fails (should not occur with valid input).

    Example:
        >>> password = b"my_secret_password"
        >>> salt = b"random_salt_32_bytes_long_!!"
        >>> key1 = derive_key(password, salt)
        >>> key2 = derive_key(password, salt)
        >>> key1 == key2
        True
    """
    if not password:
        raise ValueError("Password must not be empty")
    if len(salt) < MIN_SALT_LENGTH:
        raise ValueError(
            f"Salt must be at least {MIN_SALT_LENGTH} bytes, got {len(salt)}"
        )

    try:
        # Use low-level API for key derivation (returns raw bytes)
        # Type.ID = Argon2id variant
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,  # Argon2id
        )
        return key
    except HashingError as e:
        raise ValueError(f"Key derivation failed: {e}") from e

