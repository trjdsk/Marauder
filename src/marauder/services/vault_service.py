"""Vault service for CRUD operations on credentials."""

import json
from pathlib import Path
from typing import Any

from marauder.models import CredentialEntry
from marauder.services.session_service import SessionService


class VaultService:
    """Service for managing credential entries in vault."""

    def __init__(self, session_service: SessionService):
        """Initialize vault service."""
        self.session_service = session_service

    def _require_unlocked(self) -> bytes:
        """Require session to be unlocked, return master key."""
        master_key = self.session_service.get_master_key()
        if master_key is None:
            raise RuntimeError("Vault is locked")
        return master_key

    def _load_entries(self) -> dict[str, CredentialEntry]:
        """Load all entries from vault."""
        master_key = self._require_unlocked()
        payload = self.session_service.vault_repo.load(master_key)

        if not payload:
            return {}

        data = json.loads(payload.decode("utf-8"))
        entries = {}
        for entry_data in data.get("entries", []):
            entry = CredentialEntry.from_dict(entry_data)
            entries[entry.id] = entry
        return entries

    def _save_entries(self, entries: dict[str, CredentialEntry]) -> None:
        """Save all entries to vault."""
        master_key = self._require_unlocked()

        entries_list = [entry.to_dict() for entry in entries.values()]
        data = {"entries": entries_list}
        payload = json.dumps(data, separators=(",", ":")).encode("utf-8")

        self.session_service.vault_repo.save(payload, master_key)

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        entry_id: str | None = None,
    ) -> CredentialEntry:
        """Add new credential entry."""
        import uuid

        entries = self._load_entries()

        if entry_id is None:
            entry_id = str(uuid.uuid4())

        if entry_id in entries:
            raise ValueError(f"Entry with id {entry_id} already exists")

        entry = CredentialEntry(
            id=entry_id,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )
        entries[entry.id] = entry
        self._save_entries(entries)
        return entry

    def get_entry(self, entry_id: str) -> CredentialEntry | None:
        """Get entry by ID."""
        entries = self._load_entries()
        return entries.get(entry_id)

    def update_entry(self, entry_id: str, **kwargs: Any) -> CredentialEntry:
        """Update entry fields."""
        entries = self._load_entries()
        if entry_id not in entries:
            raise ValueError(f"Entry {entry_id} not found")

        entry = entries[entry_id]
        entry.update(**kwargs)
        self._save_entries(entries)
        return entry

    def delete_entry(self, entry_id: str) -> None:
        """Delete entry by ID."""
        entries = self._load_entries()
        if entry_id not in entries:
            raise ValueError(f"Entry {entry_id} not found")

        del entries[entry_id]
        self._save_entries(entries)

    def list_entries(self) -> list[CredentialEntry]:
        """List all entries."""
        entries = self._load_entries()
        return list(entries.values())

    def search_entries(self, query: str) -> list[CredentialEntry]:
        """Search entries by title, username, url, or notes (case-insensitive)."""
        entries = self._load_entries()
        query_lower = query.lower()

        results = []
        for entry in entries.values():
            if (
                query_lower in entry.title.lower()
                or query_lower in entry.username.lower()
                or query_lower in entry.url.lower()
                or query_lower in entry.notes.lower()
            ):
                results.append(entry)

        return results

