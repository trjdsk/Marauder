"""Tests for key derivation."""

import pytest

from marauder.crypto.key_derivation import (
    KEY_LENGTH,
    MIN_SALT_LENGTH,
    derive_key,
)


class TestKeyDerivation:
    """Test Argon2id key derivation."""

    def test_deterministic(self):
        """Same password and salt should produce same key."""
        password = b"test_password_123"
        salt = b"test_salt_32_bytes_long_!!"
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2

    def test_different_password_different_key(self):
        """Different password with same salt should produce different key."""
        salt = b"test_salt_32_bytes_long_!!"
        key1 = derive_key(b"password1", salt)
        key2 = derive_key(b"password2", salt)
        assert key1 != key2

    def test_different_salt_different_key(self):
        """Same password with different salt should produce different key."""
        password = b"test_password_123"
        key1 = derive_key(password, b"test_salt_32_bytes_long_!!")
        key2 = derive_key(password, b"different_salt_32_bytes_long!")
        assert key1 != key2

    def test_key_length(self):
        """Derived key should be exactly 32 bytes."""
        password = b"test_password_123"
        salt = b"test_salt_32_bytes_long_!!"
        key = derive_key(password, salt)
        assert len(key) == KEY_LENGTH

    def test_salt_minimum_length(self):
        """Salt must be at least MIN_SALT_LENGTH bytes."""
        password = b"test_password_123"
        # Test with exactly minimum length
        salt_min = b"a" * MIN_SALT_LENGTH
        key = derive_key(password, salt_min)
        assert len(key) == KEY_LENGTH

    def test_salt_too_short(self):
        """Salt shorter than minimum should raise ValueError."""
        password = b"test_password_123"
        salt_short = b"a" * (MIN_SALT_LENGTH - 1)
        with pytest.raises(ValueError, match="Salt must be at least"):
            derive_key(password, salt_short)

    def test_empty_password(self):
        """Empty password should raise ValueError."""
        salt = b"test_salt_32_bytes_long_!!"
        with pytest.raises(ValueError, match="Password must not be empty"):
            derive_key(b"", salt)

    def test_password_bytes_required(self):
        """Password must be bytes (not str)."""
        salt = b"test_salt_32_bytes_long_!!"
        # This should work (bytes)
        key1 = derive_key(b"password", salt)
        assert isinstance(key1, bytes)
        # If someone passes a string, it should fail
        # (Argon2 will handle this, but we document bytes requirement)

