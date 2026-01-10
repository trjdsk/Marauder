"""Vault format with versioning and corruption detection."""

import struct
from typing import NamedTuple

from marauder.crypto.encryption import AESGCM, KEY_LENGTH
from marauder.crypto.random import generate_random_bytes

VAULT_MAGIC = b"MRDR"
VAULT_VERSION = 1
HEADER_SIZE = 64
MAGIC_SIZE = 4
VERSION_SIZE = 2
SALT_SIZE = 32
NONCE_SIZE = 12
RESERVED_SIZE = 14


class VaultHeader(NamedTuple):
    """Vault file header structure."""

    magic: bytes
    version: int
    salt: bytes
    nonce: bytes

    @classmethod
    def create(cls) -> "VaultHeader":
        """Create a new vault header with random salt and nonce."""
        return cls(
            magic=VAULT_MAGIC,
            version=VAULT_VERSION,
            salt=generate_random_bytes(SALT_SIZE),
            nonce=generate_random_bytes(NONCE_SIZE),
        )

    def serialize(self) -> bytes:
        """Serialize header to bytes."""
        return struct.pack(
            f"4s H {SALT_SIZE}s {NONCE_SIZE}s {RESERVED_SIZE}s",
            self.magic,
            self.version,
            self.salt,
            self.nonce,
            b"\x00" * RESERVED_SIZE,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "VaultHeader":
        """Deserialize header from bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} < {HEADER_SIZE}")

        magic, version, salt, nonce, _ = struct.unpack(
            f"4s H {SALT_SIZE}s {NONCE_SIZE}s {RESERVED_SIZE}s", data[:HEADER_SIZE]
        )

        if magic != VAULT_MAGIC:
            raise ValueError(f"Invalid magic: expected {VAULT_MAGIC}, got {magic}")

        if version > VAULT_VERSION:
            raise ValueError(
                f"Unsupported version: {version} > {VAULT_VERSION}"
            )

        return cls(magic=magic, version=version, salt=salt, nonce=nonce)


def pack_vault(payload: bytes, key: bytes, header: VaultHeader | None = None) -> bytes:
    """Pack payload into vault format with header and encryption."""
    if header is None:
        header = VaultHeader.create()
    header_bytes = header.serialize()

    from marauder.crypto.encryption import AESGCM, KEY_LENGTH

    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    aad = header_bytes
    ciphertext = aesgcm.encrypt(header.nonce, payload, aad)

    return header_bytes + ciphertext


def unpack_vault(vault_data: bytes, key: bytes) -> bytes:
    """Unpack vault format, verify header, and decrypt payload."""
    if len(vault_data) < HEADER_SIZE:
        raise ValueError("Vault data too short")

    header_data = vault_data[:HEADER_SIZE]
    ciphertext = vault_data[HEADER_SIZE:]

    header = VaultHeader.deserialize(header_data)

    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    aad = header_data
    try:
        payload = aesgcm.decrypt(header.nonce, ciphertext, aad)
        return payload
    except Exception as e:
        raise ValueError(f"Vault decryption failed: {e}") from e

