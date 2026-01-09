"""Tests for vault repository."""

import os
import tempfile
from pathlib import Path

import pytest

from marauder.crypto.random import generate_random_bytes
from marauder.vault.repository import VaultRepository


class TestVaultRepository:
    """Test vault repository operations."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def vault_path(self, temp_dir):
        """Create vault path in temp directory."""
        return temp_dir / "test_vault.mrdr"

    @pytest.fixture
    def master_key(self):
        """Generate master key for tests."""
        return generate_random_bytes(32)

    @pytest.fixture
    def repo(self, vault_path):
        """Create vault repository."""
        return VaultRepository(vault_path)

    def test_save_load_roundtrip(self, repo, master_key):
        """Save and load should preserve data."""
        payload = b"test vault data"
        repo.save(payload, master_key)
        loaded = repo.load(master_key)
        assert loaded == payload

    def test_load_nonexistent(self, repo, master_key):
        """Loading non-existent vault should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            repo.load(master_key)

    def test_corrupt_header_rejection(self, repo, master_key):
        """Corrupted header should be rejected."""
        payload = b"test data"
        repo.save(payload, master_key)

        with open(repo.vault_path, "r+b") as f:
            f.seek(0)
            f.write(b"XXXX")

        with pytest.raises(ValueError, match="Invalid magic"):
            repo.load(master_key)

    def test_partial_file_write_recovery(self, repo, master_key):
        """Partial write should not corrupt existing vault."""
        payload1 = b"original data"
        repo.save(payload1, master_key)

        temp_path = repo.vault_path.with_suffix(repo.temp_suffix)
        with open(temp_path, "wb") as f:
            f.write(b"partial")

        if temp_path.exists():
            temp_path.unlink()

        loaded = repo.load(master_key)
        assert loaded == payload1

    def test_atomic_write_on_crash(self, repo, master_key):
        """Vault should survive crash mid-write."""
        payload1 = b"original data"
        repo.save(payload1, master_key)

        temp_path = repo.vault_path.with_suffix(repo.temp_suffix)
        with open(temp_path, "wb") as f:
            f.write(b"incomplete write")

        try:
            with open(temp_path, "wb") as f:
                f.write(b"partial")
                raise OSError("Simulated crash")
        except OSError:
            pass

        if temp_path.exists():
            temp_path.unlink()

        loaded = repo.load(master_key)
        assert loaded == payload1

    def test_wrong_key_rejection(self, repo, master_key):
        """Wrong master key should be rejected."""
        payload = b"test data"
        repo.save(payload, master_key)

        wrong_key = generate_random_bytes(32)
        with pytest.raises(ValueError, match="Vault decryption failed"):
            repo.load(wrong_key)

    def test_exists(self, repo, master_key):
        """Exists should return correct status."""
        assert not repo.exists()
        repo.save(b"test", master_key)
        assert repo.exists()

    def test_delete(self, repo, master_key):
        """Delete should remove vault file."""
        repo.save(b"test", master_key)
        assert repo.exists()
        repo.delete()
        assert not repo.exists()

    def test_empty_payload(self, repo, master_key):
        """Empty payload should work."""
        payload = b""
        repo.save(payload, master_key)
        loaded = repo.load(master_key)
        assert loaded == payload

    def test_large_payload(self, repo, master_key):
        """Large payload should work."""
        payload = b"x" * 100000
        repo.save(payload, master_key)
        loaded = repo.load(master_key)
        assert loaded == payload

    def test_multiple_saves(self, repo, master_key):
        """Multiple saves should update vault."""
        payload1 = b"first"
        payload2 = b"second"

        repo.save(payload1, master_key)
        assert repo.load(master_key) == payload1

        repo.save(payload2, master_key)
        assert repo.load(master_key) == payload2

