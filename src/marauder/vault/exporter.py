"""Vault import/export functionality with validation."""

import json
from typing import Any

from marauder.models import CredentialEntry
from marauder.services.session_service import SessionService
from marauder.services.vault_service import VaultService

EXPORT_SCHEMA_VERSION = 1


class ExportError(Exception):
    """Error during export operation."""

    pass


class ImportError(Exception):
    """Error during import operation."""

    pass


class SchemaValidationError(ImportError):
    """Schema validation failed."""

    pass


def validate_export_schema(data: dict[str, Any]) -> None:
    """Validate exported JSON schema."""
    if not isinstance(data, dict):
        raise SchemaValidationError("Root must be a dictionary")

    if "version" not in data:
        raise SchemaValidationError("Missing 'version' field")
    if not isinstance(data["version"], int):
        raise SchemaValidationError("'version' must be an integer")
    if data["version"] != EXPORT_SCHEMA_VERSION:
        raise SchemaValidationError(
            f"Unsupported version: {data['version']} != {EXPORT_SCHEMA_VERSION}"
        )

    if "entries" not in data:
        raise SchemaValidationError("Missing 'entries' field")
    if not isinstance(data["entries"], list):
        raise SchemaValidationError("'entries' must be a list")

    required_fields = {"id", "title", "username", "password"}
    for i, entry in enumerate(data["entries"]):
        if not isinstance(entry, dict):
            raise SchemaValidationError(f"Entry {i} must be a dictionary")

        for field in required_fields:
            if field not in entry:
                raise SchemaValidationError(f"Entry {i} missing required field: {field}")
            if not isinstance(entry[field], str):
                raise SchemaValidationError(f"Entry {i} field '{field}' must be a string")

        optional_fields = {"url", "notes", "created_at", "updated_at"}
        for field in optional_fields:
            if field in entry:
                if field in ("created_at", "updated_at"):
                    if not isinstance(entry[field], (int, float)):
                        raise SchemaValidationError(
                            f"Entry {i} field '{field}' must be a number"
                        )
                else:
                    if not isinstance(entry[field], str):
                        raise SchemaValidationError(
                            f"Entry {i} field '{field}' must be a string"
                        )


def export_vault(vault_service: VaultService, confirm: bool = False) -> str:
    """Export vault to plaintext JSON. Requires confirm=True."""
    if not confirm:
        raise ExportError(
            "Export requires explicit confirmation. "
            "WARNING: Export creates plaintext JSON containing all passwords. "
            "This file is NOT encrypted and should be handled with extreme care."
        )

    entries = vault_service.list_entries()
    export_data = {
        "version": EXPORT_SCHEMA_VERSION,
        "entries": [entry.to_dict() for entry in entries],
    }

    return json.dumps(export_data, indent=2)


def import_vault(
    vault_service: VaultService,
    json_data: str,
    merge_duplicates: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Import vault from plaintext JSON. Requires confirm=True. Returns import stats."""
    if not confirm:
        raise ImportError(
            "Import requires explicit confirmation. "
            "Imported data will be immediately re-encrypted and stored in vault."
        )

    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise ImportError(f"Invalid JSON: {e}") from e

    validate_export_schema(data)

    existing_entries = {e.id: e for e in vault_service.list_entries()}
    imported = 0
    skipped = 0
    merged = 0
    errors = []

    for entry_data in data["entries"]:
        try:
            entry = CredentialEntry.from_dict(entry_data)

            if entry.id in existing_entries:
                if merge_duplicates:
                    existing = existing_entries[entry.id]
                    vault_service.update_entry(
                        entry.id,
                        title=entry.title,
                        username=entry.username,
                        password=entry.password,
                        url=entry.url,
                        notes=entry.notes,
                    )
                    merged += 1
                else:
                    skipped += 1
                    errors.append(f"Duplicate entry ID: {entry.id}")
            else:
                entries_dict = vault_service._load_entries()
                entries_dict[entry.id] = entry
                vault_service._save_entries(entries_dict)
                imported += 1
        except Exception as e:
            errors.append(f"Failed to import entry {entry_data.get('id', 'unknown')}: {e}")

    return {
        "imported": imported,
        "skipped": skipped,
        "merged": merged,
        "errors": errors,
    }

