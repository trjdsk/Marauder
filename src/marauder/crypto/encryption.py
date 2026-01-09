"""AES-256-GCM encryption and decryption."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from marauder.crypto.random import generate_random_bytes

NONCE_LENGTH = 12
KEY_LENGTH = 32


def encrypt(
    plaintext: bytes, key: bytes, associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM. Returns (ciphertext, nonce)."""
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
    """Decrypt ciphertext using AES-256-GCM. Raises InvalidTag if tampered."""
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


