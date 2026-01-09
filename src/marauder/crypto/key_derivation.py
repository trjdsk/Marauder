"""Key derivation using Argon2id."""

from argon2 import Type
from argon2.low_level import hash_secret_raw
from argon2.exceptions import HashingError


ARGON2_MEMORY_COST = 65536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
KEY_LENGTH = 32
MIN_SALT_LENGTH = 16


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from password using Argon2id (OWASP parameters)."""
    if not password:
        raise ValueError("Password must not be empty")
    if len(salt) < MIN_SALT_LENGTH:
        raise ValueError(
            f"Salt must be at least {MIN_SALT_LENGTH} bytes, got {len(salt)}"
        )

    try:
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,
        )
        return key
    except HashingError as e:
        raise ValueError(f"Key derivation failed: {e}") from e

