"""Tests for authentication service."""

import tempfile
from pathlib import Path

import pytest

from marauder.crypto.random import generate_random_bytes
from marauder.services.auth_service import AuthService
from marauder.vault.repository import VaultRepository


class TestAuthService:
    """Test authentication service."""

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
    def password(self):
        """Generate password for tests."""
        return b"test_password_123"

    @pytest.fixture
    def auth_service(self, vault_path):
        """Create authentication service."""
        return AuthService(vault_path)

    def test_unlock_success(self, auth_service, vault_path, password):
        """Unlock should succeed with correct password."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        assert auth_service.unlock(password)

    def test_unlock_failure_wrong_password(self, auth_service, vault_path, password):
        """Unlock should fail with wrong password."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        wrong_password = b"wrong_password"
        assert not auth_service.unlock(wrong_password)

    def test_unlock_failure_no_vault(self, auth_service):
        """Unlock should fail if vault doesn't exist."""
        assert not auth_service.unlock(b"password")

    def test_parallel_unlock_blocked(self, auth_service, vault_path, password):
        """Parallel unlock attempts should be blocked."""
        import threading

        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        results = []

        def attempt_unlock():
            results.append(auth_service.unlock(password))

        threads = [threading.Thread(target=attempt_unlock) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1

    def test_get_salt(self, auth_service, vault_path, password):
        """Get salt should return salt from vault."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        salt = auth_service.get_salt()
        assert salt is not None
        assert len(salt) == 32
        assert salt == header.salt

    def test_get_salt_no_vault(self, auth_service):
        """Get salt should return None if vault doesn't exist."""
        assert auth_service.get_salt() is None


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Helper function for key derivation."""
    from marauder.crypto.key_derivation import derive_key as _derive_key

    return _derive_key(password, salt)

