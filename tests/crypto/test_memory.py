"""Tests for memory zeroing utilities."""

import pytest

from marauder.crypto.memory import secure_zero


class TestMemoryZeroing:
    """Test secure memory zeroing."""

    def test_bytearray_zeroing(self):
        """Mutable bytearray should be zeroed in-place."""
        data = bytearray(b"secret data")
        original_id = id(data)
        secure_zero(data)
        # ID should be the same (same object)
        assert id(data) == original_id
        # All bytes should be zero
        assert all(b == 0 for b in data)

    def test_bytearray_zeroing_large(self):
        """Large bytearray should be zeroed."""
        data = bytearray(b"x" * 1000)
        secure_zero(data)
        assert all(b == 0 for b in data)

    def test_bytes_handling(self):
        """Immutable bytes should be handled gracefully."""
        data = b"secret data"
        # Should not raise an error, but cannot zero immutable bytes
        secure_zero(data)
        # Original bytes should be unchanged (immutable)
        assert data == b"secret data"

    def test_best_effort_verification(self):
        """Attempt to verify zeroing works (best-effort)."""
        # Test with multiple bytearrays
        for _ in range(10):
            data = bytearray(b"test data " * 10)
            secure_zero(data)
            # Verify all bytes are zero
            assert all(b == 0 for b in data), "Memory zeroing failed"

    def test_empty_bytearray(self):
        """Empty bytearray should be handled correctly."""
        data = bytearray()
        secure_zero(data)
        assert len(data) == 0

    def test_invalid_type(self):
        """Invalid type should raise TypeError."""
        with pytest.raises(TypeError):
            secure_zero("not bytes or bytearray")
        with pytest.raises(TypeError):
            secure_zero(123)
        with pytest.raises(TypeError):
            secure_zero([1, 2, 3])

