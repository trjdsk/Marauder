"""Tests for vault format."""

import pytest

from marauder.crypto.random import generate_random_bytes
from marauder.vault.format import (
    HEADER_SIZE,
    VAULT_MAGIC,
    VAULT_VERSION,
    VaultHeader,
    pack_vault,
    unpack_vault,
)


class TestVaultHeader:
    """Test vault header operations."""

    def test_create_header(self):
        """Header creation should generate random salt and nonce."""
        header1 = VaultHeader.create()
        header2 = VaultHeader.create()

        assert header1.magic == VAULT_MAGIC
        assert header1.version == VAULT_VERSION
        assert len(header1.salt) == 32
        assert len(header1.nonce) == 12
        assert header1.salt != header2.salt
        assert header1.nonce != header2.nonce

    def test_serialize_deserialize(self):
        """Header should serialize and deserialize correctly."""
        header = VaultHeader.create()
        data = header.serialize()
        assert len(data) == HEADER_SIZE

        restored = VaultHeader.deserialize(data)
        assert restored.magic == header.magic
        assert restored.version == header.version
        assert restored.salt == header.salt
        assert restored.nonce == header.nonce

    def test_invalid_magic(self):
        """Invalid magic should raise ValueError."""
        header = VaultHeader.create()
        data = header.serialize()
        corrupted = b"XXXX" + data[4:]
        with pytest.raises(ValueError, match="Invalid magic"):
            VaultHeader.deserialize(corrupted)

    def test_unsupported_version(self):
        """Unsupported version should raise ValueError."""
        header = VaultHeader.create()
        data = header.serialize()
        corrupted = data[:4] + (9999).to_bytes(2, "big") + data[6:]
        with pytest.raises(ValueError, match="Unsupported version"):
            VaultHeader.deserialize(corrupted)

    def test_header_too_short(self):
        """Header too short should raise ValueError."""
        with pytest.raises(ValueError, match="Header too short"):
            VaultHeader.deserialize(b"short")


class TestVaultFormat:
    """Test vault packing and unpacking."""

    def test_pack_unpack_roundtrip(self):
        """Pack and unpack should preserve payload."""
        key = generate_random_bytes(32)
        payload = b"test payload data"

        vault_data = pack_vault(payload, key)
        unpacked = unpack_vault(vault_data, key)

        assert unpacked == payload

    def test_corrupt_header_rejection(self):
        """Corrupted header should be rejected."""
        key = generate_random_bytes(32)
        payload = b"test payload"

        vault_data = pack_vault(payload, key)
        corrupted = b"XXXX" + vault_data[4:]

        with pytest.raises(ValueError, match="Invalid magic"):
            unpack_vault(corrupted, key)

    def test_corrupt_ciphertext_rejection(self):
        """Corrupted ciphertext should be rejected."""
        key = generate_random_bytes(32)
        payload = b"test payload"

        vault_data = pack_vault(payload, key)
        corrupted = vault_data[:HEADER_SIZE] + b"corrupted" + vault_data[HEADER_SIZE + 9 :]

        with pytest.raises(ValueError, match="Vault decryption failed"):
            unpack_vault(corrupted, key)

    def test_wrong_key_rejection(self):
        """Wrong key should be rejected."""
        key1 = generate_random_bytes(32)
        key2 = generate_random_bytes(32)
        payload = b"test payload"

        vault_data = pack_vault(payload, key1)
        with pytest.raises(ValueError, match="Vault decryption failed"):
            unpack_vault(vault_data, key2)

    def test_downgrade_attack_prevention(self):
        """Version downgrade should be detected."""
        key = generate_random_bytes(32)
        payload = b"test payload"

        vault_data = pack_vault(payload, key)
        header = VaultHeader.deserialize(vault_data[:HEADER_SIZE])

        assert header.version == VAULT_VERSION

        if VAULT_VERSION > 1:
            corrupted = (
                vault_data[:4]
                + (VAULT_VERSION - 1).to_bytes(2, "big")
                + vault_data[6:]
            )
            with pytest.raises(ValueError, match="Unsupported version"):
                unpack_vault(corrupted, key)

    def test_associated_data_binding(self):
        """Header should be bound to ciphertext via AAD."""
        key = generate_random_bytes(32)
        payload = b"test payload"

        vault_data = pack_vault(payload, key)
        header_data = vault_data[:HEADER_SIZE]
        ciphertext = vault_data[HEADER_SIZE:]

        modified_header = header_data[:4] + b"XX" + header_data[6:]
        modified_vault = modified_header + ciphertext

        with pytest.raises(ValueError):
            unpack_vault(modified_vault, key)

    def test_empty_payload(self):
        """Empty payload should work."""
        key = generate_random_bytes(32)
        payload = b""

        vault_data = pack_vault(payload, key)
        unpacked = unpack_vault(vault_data, key)

        assert unpacked == payload

    def test_large_payload(self):
        """Large payload should work."""
        key = generate_random_bytes(32)
        payload = b"x" * 10000

        vault_data = pack_vault(payload, key)
        unpacked = unpack_vault(vault_data, key)

        assert unpacked == payload

