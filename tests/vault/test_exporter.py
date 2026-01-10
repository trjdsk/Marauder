"""Tests for vault import/export."""

import json
import tempfile
from pathlib import Path

import pytest

from marauder.models import CredentialEntry
from marauder.services.session_service import SessionService
from marauder.services.vault_service import VaultService
from marauder.vault.exporter import (
    ExportError,
    ImportError,
    SchemaValidationError,
    export_vault,
    import_vault,
)
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

    payload = json.dumps({"entries": []}).encode("utf-8")
    vault_data = pack_vault(payload, master_key, header)
    vault_path.write_bytes(vault_data)

    service.unlock(password)
    return service


@pytest.fixture
def vault_service(session_service):
    """Create vault service."""
    return VaultService(session_service)


class TestExport:
    """Test export functionality."""

    def test_export_requires_confirmation(self, vault_service):
        """Export should require explicit confirmation."""
        with pytest.raises(ExportError, match="requires explicit confirmation"):
            export_vault(vault_service, confirm=False)

    def test_export_plaintext_warning(self, vault_service):
        """Export error should warn about plaintext."""
        with pytest.raises(ExportError, match="plaintext JSON"):
            export_vault(vault_service, confirm=False)

    def test_export_empty_vault(self, vault_service):
        """Export empty vault should work."""
        json_data = export_vault(vault_service, confirm=True)
        data = json.loads(json_data)

        assert data["version"] == 1
        assert data["entries"] == []

    def test_export_with_entries(self, vault_service):
        """Export should include all entries."""
        entry1 = vault_service.add_entry(
            title="Site 1", username="user1", password="pass1"
        )
        entry2 = vault_service.add_entry(
            title="Site 2", username="user2", password="pass2", url="https://example.com"
        )

        json_data = export_vault(vault_service, confirm=True)
        data = json.loads(json_data)

        assert data["version"] == 1
        assert len(data["entries"]) == 2

        entry_dicts = {e["id"]: e for e in data["entries"]}
        assert entry1.id in entry_dicts
        assert entry2.id in entry_dicts
        assert entry_dicts[entry1.id]["title"] == "Site 1"
        assert entry_dicts[entry2.id]["url"] == "https://example.com"

    def test_export_contains_plaintext_passwords(self, vault_service):
        """Export should contain plaintext passwords (security risk)."""
        vault_service.add_entry(
            title="Test", username="user", password="secret_password_123"
        )

        json_data = export_vault(vault_service, confirm=True)
        assert "secret_password_123" in json_data


class TestImport:
    """Test import functionality."""

    def test_import_requires_confirmation(self, vault_service):
        """Import should require explicit confirmation."""
        json_data = json.dumps({"version": 1, "entries": []})

        with pytest.raises(ImportError, match="requires explicit confirmation"):
            import_vault(vault_service, json_data, confirm=False)

    def test_import_valid_schema(self, vault_service):
        """Import valid schema should work."""
        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test-id",
                        "title": "Test Site",
                        "username": "user",
                        "password": "pass",
                    }
                ],
            }
        )

        result = import_vault(vault_service, json_data, confirm=True)
        assert result["imported"] == 1
        assert result["skipped"] == 0
        assert result["merged"] == 0
        assert len(result["errors"]) == 0

        entry = vault_service.get_entry("test-id")
        assert entry is not None
        assert entry.title == "Test Site"

    def test_schema_validation_failure_missing_version(self, vault_service):
        """Schema validation should fail on missing version."""
        json_data = json.dumps({"entries": []})

        with pytest.raises(SchemaValidationError, match="Missing 'version'"):
            import_vault(vault_service, json_data, confirm=True)

    def test_schema_validation_failure_wrong_version(self, vault_service):
        """Schema validation should fail on wrong version."""
        json_data = json.dumps({"version": 999, "entries": []})

        with pytest.raises(SchemaValidationError, match="Unsupported version"):
            import_vault(vault_service, json_data, confirm=True)

    def test_schema_validation_failure_missing_entries(self, vault_service):
        """Schema validation should fail on missing entries."""
        json_data = json.dumps({"version": 1})

        with pytest.raises(SchemaValidationError, match="Missing 'entries'"):
            import_vault(vault_service, json_data, confirm=True)

    def test_schema_validation_failure_invalid_entry(self, vault_service):
        """Schema validation should fail on invalid entry."""
        json_data = json.dumps(
            {
                "version": 1,
                "entries": [{"id": "test", "title": "Test"}],
            }
        )

        with pytest.raises(SchemaValidationError, match="missing required field"):
            import_vault(vault_service, json_data, confirm=True)

    def test_schema_validation_failure_wrong_type(self, vault_service):
        """Schema validation should fail on wrong field type."""
        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test",
                        "title": "Test",
                        "username": "user",
                        "password": 123,
                    }
                ],
            }
        )

        with pytest.raises(SchemaValidationError, match="must be a string"):
            import_vault(vault_service, json_data, confirm=True)

    def test_duplicate_merge_logic(self, vault_service):
        """Duplicate entries should be merged when merge_duplicates=True."""
        existing = vault_service.add_entry(
            title="Original", username="user", password="oldpass", entry_id="test-id"
        )

        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test-id",
                        "title": "Updated",
                        "username": "user",
                        "password": "newpass",
                    }
                ],
            }
        )

        result = import_vault(vault_service, json_data, merge_duplicates=True, confirm=True)
        assert result["imported"] == 0
        assert result["skipped"] == 0
        assert result["merged"] == 1

        entry = vault_service.get_entry("test-id")
        assert entry.title == "Updated"
        assert entry.password == "newpass"

    def test_no_silent_overwrites(self, vault_service):
        """Duplicates should not silently overwrite when merge_duplicates=False."""
        vault_service.add_entry(
            title="Original", username="user", password="oldpass", entry_id="test-id"
        )

        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test-id",
                        "title": "New",
                        "username": "user",
                        "password": "newpass",
                    }
                ],
            }
        )

        result = import_vault(vault_service, json_data, merge_duplicates=False, confirm=True)
        assert result["imported"] == 0
        assert result["skipped"] == 1
        assert result["merged"] == 0
        assert len(result["errors"]) == 1
        assert "Duplicate entry ID" in result["errors"][0]

        entry = vault_service.get_entry("test-id")
        assert entry.title == "Original"
        assert entry.password == "oldpass"

    def test_import_multiple_entries(self, vault_service):
        """Import should handle multiple entries."""
        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "id1",
                        "title": "Site 1",
                        "username": "user1",
                        "password": "pass1",
                    },
                    {
                        "id": "id2",
                        "title": "Site 2",
                        "username": "user2",
                        "password": "pass2",
                        "url": "https://example.com",
                        "notes": "Test notes",
                    },
                ],
            }
        )

        result = import_vault(vault_service, json_data, confirm=True)
        assert result["imported"] == 2
        assert result["skipped"] == 0

        assert vault_service.get_entry("id1") is not None
        assert vault_service.get_entry("id2") is not None

    def test_import_invalid_json(self, vault_service):
        """Import should fail on invalid JSON."""
        with pytest.raises(ImportError, match="Invalid JSON"):
            import_vault(vault_service, "not json", confirm=True)

    def test_import_immediate_re_encryption(self, vault_service, vault_path):
        """Imported data should be immediately re-encrypted."""
        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test-id",
                        "title": "Test",
                        "username": "user",
                        "password": "secret_password",
                    }
                ],
            }
        )

        import_vault(vault_service, json_data, confirm=True)

        vault_data = vault_path.read_bytes()
        vault_text = vault_data.decode("utf-8", errors="ignore")

        assert "secret_password" not in vault_text
        assert "Test" not in vault_text

    def test_import_with_timestamps(self, vault_service):
        """Import should preserve timestamps if present."""
        import time

        created = time.time() - 1000
        updated = time.time() - 500

        json_data = json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "id": "test-id",
                        "title": "Test",
                        "username": "user",
                        "password": "pass",
                        "created_at": created,
                        "updated_at": updated,
                    }
                ],
            }
        )

        import_vault(vault_service, json_data, confirm=True)
        entry = vault_service.get_entry("test-id")

        assert entry.created_at == created
        assert entry.updated_at == updated

