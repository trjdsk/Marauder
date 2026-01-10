"""Authentication service for vault unlocking."""

import threading
from pathlib import Path

from marauder.crypto.key_derivation import derive_key
from marauder.vault.format import VaultHeader
from marauder.vault.repository import VaultRepository


class AuthService:
    """Service for authenticating and unlocking vaults."""

    def __init__(self, vault_path: Path):
        """Initialize authentication service."""
        self.vault_repo = VaultRepository(vault_path)
        self._lock = threading.Lock()
        self._unlock_in_progress = False

    def unlock(self, password: bytes) -> bool:
        """
        Unlock vault with password. Returns True if successful.

        Blocks parallel unlock attempts. Derives master key from password
        and verifies by attempting to load vault.
        """
        with self._lock:
            if self._unlock_in_progress:
                return False

            self._unlock_in_progress = True

        try:
            if not self.vault_repo.exists():
                return False

            vault_data = self.vault_repo.vault_path.read_bytes()
            if len(vault_data) < 64:
                return False

            header = VaultHeader.deserialize(vault_data[:64])
            master_key = derive_key(password, header.salt)

            try:
                self.vault_repo.load(master_key)
                return True
            except Exception:
                return False
        finally:
            with self._lock:
                self._unlock_in_progress = False

    def get_salt(self) -> bytes | None:
        """Get salt from vault header if vault exists."""
        if not self.vault_repo.exists():
            return None

        try:
            vault_data = self.vault_repo.vault_path.read_bytes()
            if len(vault_data) < 64:
                return None
            header = VaultHeader.deserialize(vault_data[:64])
            return header.salt
        except Exception:
            return None

