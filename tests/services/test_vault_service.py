"""Tests for vault service."""

import tempfile
import time
from pathlib import Path

import pytest

from marauder.models import CredentialEntry
from marauder.services.session_service import SessionService
from marauder.services.vault_service import VaultService
from marauder.vault.format import VaultHeader, pack_vault


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Helper function for key derivation."""
    from marauder.crypto.key_derivation import derive_key as _derive_key

    return _derive_key(password, salt)


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def vault_path(temp_dir):
    """Create vault path in temp directory."""
    return temp_dir / "test_vault.mrdr"


@pytest.fixture
def password():
    """Generate password for tests."""
    return b"test_password_123"


@pytest.fixture
def session_service(vault_path, password):
    """Create and unlock session service."""
    service = SessionService(vault_path)
    header = VaultHeader.create()
    master_key = derive_key(password, header.salt)

    import json

    payload = json.dumps({"entries": []}).encode("utf-8")
    vault_data = pack_vault(payload, master_key, header)
    vault_path.write_bytes(vault_data)

    service.unlock(password)
    return service


@pytest.fixture
def vault_service(session_service):
    """Create vault service."""
    return VaultService(session_service)


class TestVaultService:
    """Test vault service CRUD operations."""

    def test_add_entry(self, vault_service):
        """Add entry should create new credential."""
        entry = vault_service.add_entry(
            title="Test Site",
            username="user@example.com",
            password="secret123",
            url="https://example.com",
            notes="Test notes",
        )

        assert entry.title == "Test Site"
        assert entry.username == "user@example.com"
        assert entry.password == "secret123"
        assert entry.url == "https://example.com"
        assert entry.notes == "Test notes"
        assert entry.id is not None
        assert entry.created_at > 0
        assert entry.updated_at > 0

    def test_get_entry(self, vault_service):
        """Get entry should retrieve saved entry."""
        entry = vault_service.add_entry(
            title="Test Site", username="user", password="pass"
        )

        retrieved = vault_service.get_entry(entry.id)
        assert retrieved is not None
        assert retrieved.title == entry.title
        assert retrieved.username == entry.username
        assert retrieved.password == entry.password

    def test_get_entry_not_found(self, vault_service):
        """Get non-existent entry should return None."""
        assert vault_service.get_entry("nonexistent") is None

    def test_update_entry(self, vault_service):
        """Update entry should modify fields."""
        entry = vault_service.add_entry(
            title="Test Site", username="user", password="pass"
        )
        original_updated = entry.updated_at

        time.sleep(0.01)
        updated = vault_service.update_entry(
            entry.id, title="Updated Title", password="newpass"
        )

        assert updated.title == "Updated Title"
        assert updated.password == "newpass"
        assert updated.username == "user"
        assert updated.updated_at > original_updated

    def test_update_entry_not_found(self, vault_service):
        """Update non-existent entry should raise ValueError."""
        with pytest.raises(ValueError, match="not found"):
            vault_service.update_entry("nonexistent", title="New")

    def test_delete_entry(self, vault_service):
        """Delete entry should remove it from vault."""
        entry = vault_service.add_entry(
            title="Test Site", username="user", password="pass"
        )

        vault_service.delete_entry(entry.id)
        assert vault_service.get_entry(entry.id) is None

    def test_delete_entry_not_found(self, vault_service):
        """Delete non-existent entry should raise ValueError."""
        with pytest.raises(ValueError, match="not found"):
            vault_service.delete_entry("nonexistent")

    def test_list_entries(self, vault_service):
        """List entries should return all entries."""
        entry1 = vault_service.add_entry(
            title="Site 1", username="user1", password="pass1"
        )
        entry2 = vault_service.add_entry(
            title="Site 2", username="user2", password="pass2"
        )

        entries = vault_service.list_entries()
        assert len(entries) == 2
        ids = {e.id for e in entries}
        assert entry1.id in ids
        assert entry2.id in ids

    def test_list_entries_empty(self, vault_service):
        """List entries on empty vault should return empty list."""
        assert vault_service.list_entries() == []

    def test_search_entries(self, vault_service):
        """Search should find matching entries."""
        vault_service.add_entry(
            title="GitHub", username="dev", password="pass", url="github.com"
        )
        vault_service.add_entry(
            title="Gmail", username="user", password="pass", notes="email account"
        )
        vault_service.add_entry(title="Other", username="other", password="pass")

        results = vault_service.search_entries("github")
        assert len(results) == 1
        assert results[0].title == "GitHub"

        results = vault_service.search_entries("GMAIL")
        assert len(results) == 1
        assert results[0].title == "Gmail"

        results = vault_service.search_entries("email")
        assert len(results) == 1
        assert results[0].title == "Gmail"

    def test_entry_crud_consistency(self, vault_service):
        """Full CRUD cycle should maintain data integrity."""
        entry = vault_service.add_entry(
            title="Original", username="user", password="pass", url="example.com"
        )

        retrieved = vault_service.get_entry(entry.id)
        assert retrieved.title == "Original"

        vault_service.update_entry(entry.id, title="Updated")
        retrieved = vault_service.get_entry(entry.id)
        assert retrieved.title == "Updated"
        assert retrieved.username == "user"

        vault_service.delete_entry(entry.id)
        assert vault_service.get_entry(entry.id) is None

    def test_duplicate_id_handling(self, vault_service):
        """Adding entry with existing ID should raise ValueError."""
        entry = vault_service.add_entry(
            title="Test", username="user", password="pass", entry_id="test-id"
        )

        with pytest.raises(ValueError, match="already exists"):
            vault_service.add_entry(
                title="Duplicate",
                username="user2",
                password="pass2",
                entry_id="test-id",
            )

    def test_no_plaintext_disk_writes(self, vault_service, vault_path):
        """Vault file should contain only encrypted data."""
        vault_service.add_entry(
            title="Secret Site",
            username="secret_user",
            password="secret_password",
            notes="secret notes",
        )

        vault_data = vault_path.read_bytes()
        vault_text = vault_data.decode("utf-8", errors="ignore")

        assert "Secret Site" not in vault_text
        assert "secret_user" not in vault_text
        assert "secret_password" not in vault_text
        assert "secret notes" not in vault_text

    def test_metadata_timestamps(self, vault_service):
        """Entries should have created_at and updated_at timestamps."""
        import time

        before = time.time()
        entry = vault_service.add_entry(
            title="Test", username="user", password="pass"
        )
        after = time.time()

        assert before <= entry.created_at <= after
        assert before <= entry.updated_at <= after
        assert entry.created_at == entry.updated_at

        time.sleep(0.01)
        updated = vault_service.update_entry(entry.id, title="Updated")
        assert updated.created_at == entry.created_at
        assert updated.updated_at > entry.updated_at

    def test_locked_vault_operations(self, vault_path, password):
        """Operations on locked vault should raise RuntimeError."""
        header = VaultHeader.create()
        master_key = derive_key(password, header.salt)

        import json

        payload = json.dumps({"entries": []}).encode("utf-8")
        vault_data = pack_vault(payload, master_key, header)
        vault_path.write_bytes(vault_data)

        session_service = SessionService(vault_path)
        vault_service = VaultService(session_service)

        with pytest.raises(RuntimeError, match="locked"):
            vault_service.add_entry(title="Test", username="user", password="pass")

        with pytest.raises(RuntimeError, match="locked"):
            vault_service.list_entries()

