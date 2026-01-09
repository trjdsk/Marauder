"""Secure random number generation."""

import secrets


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Uses the operating system's secure random number generator to produce
    cryptographically strong random bytes suitable for cryptographic operations.

    Args:
        length: Number of bytes to generate. Must be at least 1.

    Returns:
        A bytes object containing the requested number of random bytes.

    Raises:
        ValueError: If length is less than 1.

    Example:
        >>> random_bytes = generate_random_bytes(32)
        >>> len(random_bytes)
        32
    """
    if length < 1:
        raise ValueError("Length must be at least 1 byte")
    return secrets.token_bytes(length)

