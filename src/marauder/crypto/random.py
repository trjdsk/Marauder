"""Secure random number generation."""

import secrets


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    if length < 1:
        raise ValueError("Length must be at least 1 byte")
    return secrets.token_bytes(length)


