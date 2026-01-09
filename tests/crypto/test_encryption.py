"""Tests for AES-256-GCM encryption and decryption."""

import pytest
from cryptography.exceptions import InvalidTag

from marauder.crypto.encryption import KEY_LENGTH, NONCE_LENGTH, decrypt, encrypt


class TestEncryption:
    """Test AES-256-GCM encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt correctly."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        ciphertext, nonce = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, nonce, key)
        assert decrypted == plaintext

    def test_wrong_key_failure(self):
        """Wrong key should raise InvalidTag."""
        key1 = b"a" * KEY_LENGTH
        key2 = b"b" * KEY_LENGTH
        plaintext = b"secret message"
        ciphertext, nonce = encrypt(plaintext, key1)
        with pytest.raises(InvalidTag):
            decrypt(ciphertext, nonce, key2)

    def test_tampered_ciphertext_failure(self):
        """Tampered ciphertext should raise InvalidTag."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        ciphertext, nonce = encrypt(plaintext, key)
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] = (tampered[0] + 1) % 256
        with pytest.raises(InvalidTag):
            decrypt(bytes(tampered), nonce, key)

    def test_tampered_nonce_failure(self):
        """Tampered nonce should raise InvalidTag."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        ciphertext, nonce = encrypt(plaintext, key)
        # Tamper with nonce
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] = (tampered_nonce[0] + 1) % 256
        with pytest.raises(InvalidTag):
            decrypt(ciphertext, bytes(tampered_nonce), key)

    def test_associated_data(self):
        """Associated data should be authenticated and verified."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        aad = b"additional authenticated data"
        ciphertext, nonce = encrypt(plaintext, key, aad)
        # Decrypt with correct AAD
        decrypted = decrypt(ciphertext, nonce, key, aad)
        assert decrypted == plaintext

    def test_wrong_associated_data_failure(self):
        """Wrong associated data should raise InvalidTag."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        aad1 = b"additional authenticated data"
        aad2 = b"different authenticated data"
        ciphertext, nonce = encrypt(plaintext, key, aad1)
        with pytest.raises(InvalidTag):
            decrypt(ciphertext, nonce, key, aad2)

    def test_different_plaintexts_different_ciphertexts(self):
        """Same key, different plaintext should produce different ciphertext."""
        key = b"a" * KEY_LENGTH
        plaintext1 = b"message one"
        plaintext2 = b"message two"
        ciphertext1, nonce1 = encrypt(plaintext1, key)
        ciphertext2, nonce2 = encrypt(plaintext2, key)
        # Ciphertexts should be different
        assert ciphertext1 != ciphertext2
        # Nonces should also be different (high probability)
        assert nonce1 != nonce2

    def test_key_length_validation(self):
        """Invalid key length should raise ValueError."""
        key_short = b"a" * (KEY_LENGTH - 1)
        key_long = b"a" * (KEY_LENGTH + 1)
        plaintext = b"secret message"
        with pytest.raises(ValueError, match="Key must be exactly"):
            encrypt(plaintext, key_short)
        with pytest.raises(ValueError, match="Key must be exactly"):
            encrypt(plaintext, key_long)
        with pytest.raises(ValueError, match="Key must be exactly"):
            decrypt(b"ciphertext", b"nonce", key_short)
        with pytest.raises(ValueError, match="Key must be exactly"):
            decrypt(b"ciphertext", b"nonce", key_long)

    def test_nonce_uniqueness(self):
        """Multiple encryptions should produce different nonces."""
        key = b"a" * KEY_LENGTH
        plaintext = b"secret message"
        nonces = []
        for _ in range(100):
            _, nonce = encrypt(plaintext, key)
            nonces.append(nonce)
        # All nonces should be unique (very high probability)
        unique_nonces = set(nonces)
        assert len(unique_nonces) == len(nonces)

    def test_nonce_length_validation(self):
        """Invalid nonce length should raise ValueError."""
        key = b"a" * KEY_LENGTH
        ciphertext = b"ciphertext"
        nonce_short = b"a" * (NONCE_LENGTH - 1)
        nonce_long = b"a" * (NONCE_LENGTH + 1)
        with pytest.raises(ValueError, match="Nonce must be exactly"):
            decrypt(ciphertext, nonce_short, key)
        with pytest.raises(ValueError, match="Nonce must be exactly"):
            decrypt(ciphertext, nonce_long, key)

    def test_empty_plaintext(self):
        """Empty plaintext should encrypt and decrypt correctly."""
        key = b"a" * KEY_LENGTH
        plaintext = b""
        ciphertext, nonce = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, nonce, key)
        assert decrypted == plaintext

    def test_large_plaintext(self):
        """Large plaintext should encrypt and decrypt correctly."""
        key = b"a" * KEY_LENGTH
        plaintext = b"x" * 10000
        ciphertext, nonce = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, nonce, key)
        assert decrypted == plaintext


