"""Domain models for credential entries."""

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CredentialEntry:
    """Credential entry model."""

    id: str
    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CredentialEntry":
        """Create entry from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            username=data["username"],
            password=data["password"],
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
        )

    def update(self, **kwargs: Any) -> None:
        """Update entry fields and set updated_at timestamp."""
        for key, value in kwargs.items():
            if hasattr(self, key) and key not in ("id", "created_at"):
                setattr(self, key, value)
        self.updated_at = time.time()

