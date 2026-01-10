"""Session management with auto-lock and timeout."""

import threading
import time
from pathlib import Path

from marauder.crypto.key_derivation import derive_key
from marauder.crypto.memory import secure_zero
from marauder.services.auth_service import AuthService
from marauder.vault.format import VaultHeader
from marauder.vault.repository import VaultRepository


class SessionService:
    """Service for managing unlocked sessions with timeout."""

    def __init__(self, vault_path: Path, idle_timeout: float = 300.0):
        """
        Initialize session service.

        Args:
            vault_path: Path to vault file
            idle_timeout: Idle timeout in seconds (default 5 minutes)
        """
        self.vault_repo = VaultRepository(vault_path)
        self.auth_service = AuthService(vault_path)
        self.idle_timeout = idle_timeout

        self._lock = threading.Lock()
        self._master_key: bytearray | None = None
        self._last_activity: float | None = None
        self._timeout_timer: threading.Timer | None = None

    def unlock(self, password: bytes) -> bool:
        """
        Unlock vault with password. Returns True if successful.

        Blocks parallel unlock attempts. Stores master key in memory
        and starts idle timeout timer.
        """
        with self._lock:
            if self._master_key is not None:
                return False

            if not self.auth_service.unlock(password):
                return False

            vault_data = self.vault_repo.vault_path.read_bytes()
            header = VaultHeader.deserialize(vault_data[:64])
            master_key_bytes = derive_key(password, header.salt)

            self._master_key = bytearray(master_key_bytes)
            self._last_activity = time.time()
            self._start_timeout_timer()

            return True

    def lock(self) -> None:
        """Lock session and wipe master key from memory."""
        with self._lock:
            self._stop_timeout_timer()
            if self._master_key is not None:
                secure_zero(self._master_key)
                self._master_key = None
            self._last_activity = None

    def is_unlocked(self) -> bool:
        """Check if session is currently unlocked."""
        with self._lock:
            return self._master_key is not None

    def get_master_key(self) -> bytes | None:
        """
        Get master key if unlocked. Updates last activity time.

        Returns None if locked. Caller should not store the returned
        bytes object longer than necessary.
        """
        with self._lock:
            if self._master_key is None:
                return None

            self._last_activity = time.time()
            self._reset_timeout_timer()
            return bytes(self._master_key)

    def _start_timeout_timer(self) -> None:
        """Start idle timeout timer."""
        self._stop_timeout_timer()
        self._timeout_timer = threading.Timer(self.idle_timeout, self._on_timeout)
        self._timeout_timer.daemon = True
        self._timeout_timer.start()

    def _stop_timeout_timer(self) -> None:
        """Stop idle timeout timer."""
        if self._timeout_timer is not None:
            self._timeout_timer.cancel()
            self._timeout_timer = None

    def _reset_timeout_timer(self) -> None:
        """Reset idle timeout timer."""
        if self._master_key is not None:
            self._start_timeout_timer()

    def _on_timeout(self) -> None:
        """Handle idle timeout - lock session."""
        self.lock()

