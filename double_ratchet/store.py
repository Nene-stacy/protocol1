"""
Session storage abstractions.

Provides a protocol (interface) and a default in-memory implementation.
For production use, replace InMemorySessionStore with a persistent backend
(SQLite, Redis, encrypted file store, etc.).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

from .ratchet import RatchetSession
from .exceptions import SessionNotFoundError


class SessionStore(ABC):
    """Abstract base class for Double Ratchet session storage."""

    @abstractmethod
    def save(self, session: RatchetSession) -> None:
        """Persist a session by its session_id."""

    @abstractmethod
    def load(self, session_id: str) -> RatchetSession:
        """Load a session by id. Raises SessionNotFoundError if absent."""

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """Delete a session."""

    @abstractmethod
    def exists(self, session_id: str) -> bool:
        """Return True if a session with this id exists."""


class InMemorySessionStore(SessionStore):
    """
    Simple in-memory session store.

    NOT suitable for production (data is lost on process exit and offers
    no concurrent access protection). Use as a reference or for testing.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}  # session_id -> JSON string

    def save(self, session: RatchetSession) -> None:
        self._sessions[session.session_id] = session.to_json()

    def load(self, session_id: str) -> RatchetSession:
        raw = self._sessions.get(session_id)
        if raw is None:
            raise SessionNotFoundError(f"Session '{session_id}' not found")
        return RatchetSession.from_json(raw)

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def exists(self, session_id: str) -> bool:
        return session_id in self._sessions

    def all_ids(self) -> list[str]:
        return list(self._sessions.keys())

    def __len__(self) -> int:
        return len(self._sessions)
