"""AES-256-GCM encryption and decryption."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from marauder.crypto.random import generate_random_bytes

NONCE_LENGTH = 12  # 96 bits for GCM
KEY_LENGTH = 32  # 256 bits for AES-256


def encrypt(
    plaintext: bytes, key: bytes, associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Uses authenticated encryption with associated data (AEAD) to provide
    both confidentiality and authenticity. Each encryption uses a unique
    nonce generated from a secure random source.

    Args:
        plaintext: The data to encrypt.
        key: The encryption key. Must be exactly 32 bytes (256 bits).
        associated_data: Optional additional authenticated data (AAD).
            This data is authenticated but not encrypted.

    Returns:
        A tuple of (ciphertext, nonce). The nonce must be stored and
        provided to decrypt() along with the ciphertext.

    Raises:
        ValueError: If key length is not 32 bytes.

    Example:
        >>> key = b"a" * 32
        >>> plaintext = b"secret message"
        >>> ciphertext, nonce = encrypt(plaintext, key)
        >>> decrypted = decrypt(ciphertext, nonce, key)
        >>> decrypted == plaintext
        True
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes, got {len(key)}")

    nonce = generate_random_bytes(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt(
    ciphertext: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.

    Verifies both the authenticity and integrity of the ciphertext before
    decryption. If the ciphertext or nonce has been tampered with, or if
    the wrong key is used, decryption will fail.

    Args:
        ciphertext: The encrypted data.
        nonce: The nonce used during encryption. Must be exactly 12 bytes.
        key: The decryption key. Must be exactly 32 bytes (256 bits).
        associated_data: Optional additional authenticated data (AAD).
            Must match the AAD used during encryption, if any.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If key or nonce length is invalid.
        InvalidTag: If decryption fails due to tampering, wrong key, or
            mismatched associated data. This indicates the ciphertext is
            not authentic.

    Example:
        >>> key = b"a" * 32
        >>> plaintext = b"secret message"
        >>> ciphertext, nonce = encrypt(plaintext, key)
        >>> decrypted = decrypt(ciphertext, nonce, key)
        >>> decrypted == plaintext
        True
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes, got {len(key)}")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(
            f"Nonce must be exactly {NONCE_LENGTH} bytes, got {len(nonce)}"
        )

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag as e:
        raise InvalidTag(
            "Decryption failed: ciphertext may be tampered or key is incorrect"
        ) from e

