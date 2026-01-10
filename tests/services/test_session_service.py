"""Tests for session service."""

import tempfile
import time
from pathlib import Path

import pytest

from marauder.crypto.random import generate_random_bytes
from marauder.services.session_service import SessionService
from marauder.vault.repository import VaultRepository


class TestSessionService:
    """Test session service."""

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
    def session_service(self, vault_path):
        """Create session service with short timeout for testing."""
        return SessionService(vault_path, idle_timeout=0.1)

    def test_unlock_lock(self, session_service, vault_path, password):
        """Unlock and lock should work correctly."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        assert session_service.unlock(password)
        assert session_service.is_unlocked()
        assert session_service.get_master_key() == master_key

        session_service.lock()
        assert not session_service.is_unlocked()
        assert session_service.get_master_key() is None

    def test_timeout_triggers_lock(self, vault_path, password):
        """Timeout should trigger automatic lock."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        service = SessionService(vault_path, idle_timeout=0.1)
        assert service.unlock(password)
        assert service.is_unlocked()

        time.sleep(0.15)
        assert not service.is_unlocked()

    def test_key_wiped_on_lock(self, session_service, vault_path, password):
        """Master key should be wiped from memory on lock."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        assert session_service.unlock(password)
        key_ref = session_service._master_key
        assert key_ref is not None
        assert bytes(key_ref) == master_key

        session_service.lock()
        assert all(b == 0 for b in key_ref)

    def test_parallel_unlock_blocked(self, session_service, vault_path, password):
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
            results.append(session_service.unlock(password))

        threads = [threading.Thread(target=attempt_unlock) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1

    def test_get_master_key_updates_activity(self, session_service, vault_path, password):
        """Getting master key should update last activity time."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        assert session_service.unlock(password)
        time.sleep(0.05)

        session_service.get_master_key()
        time.sleep(0.05)

        assert session_service.is_unlocked()

    def test_unlock_when_already_unlocked(self, session_service, vault_path, password):
        """Unlock when already unlocked should return False."""
        from marauder.vault.format import VaultHeader, pack_vault

        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        payload = b"test data"
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        assert session_service.unlock(password)
        assert not session_service.unlock(password)

    def test_get_master_key_when_locked(self, session_service):
        """Getting master key when locked should return None."""
        assert session_service.get_master_key() is None


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Helper function for key derivation."""
    from marauder.crypto.key_derivation import derive_key as _derive_key

    return _derive_key(password, salt)

