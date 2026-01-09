"""Vault repository with atomic writes and corruption detection."""

import os
from pathlib import Path

from marauder.vault.format import pack_vault, unpack_vault


class VaultRepository:
    """Repository for vault file operations with atomic writes."""

    def __init__(self, vault_path: Path):
        """Initialize vault repository."""
        self.vault_path = Path(vault_path)
        self.temp_suffix = ".tmp"

    def save(self, payload: bytes, master_key: bytes) -> None:
        """Save payload to vault with atomic write."""
        vault_data = pack_vault(payload, master_key)

        temp_path = self.vault_path.with_suffix(self.temp_suffix)

        try:
            with open(temp_path, "wb") as f:
                f.write(vault_data)
                f.flush()
                os.fsync(f.fileno())

            temp_path.replace(self.vault_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    def load(self, master_key: bytes) -> bytes:
        """Load payload from vault with corruption detection."""
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault not found: {self.vault_path}")

        with open(self.vault_path, "rb") as f:
            vault_data = f.read()

        if len(vault_data) < 64:
            raise ValueError("Vault file too short or corrupted")

        try:
            payload = unpack_vault(vault_data, master_key)
            return payload
        except Exception as e:
            raise ValueError(f"Failed to load vault: {e}") from e

    def exists(self) -> bool:
        """Check if vault file exists."""
        return self.vault_path.exists()

    def delete(self) -> None:
        """Delete vault file."""
        if self.vault_path.exists():
            self.vault_path.unlink()

