"""Persistence implementations for trusted context records."""

from __future__ import annotations

import threading
from typing import Any, Mapping

from .exceptions import PersistenceError


class TrustedContextStore:
    """Thread-safe in-memory store for accepted canonical records."""

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def persist(self, record: Mapping[str, Any]) -> None:
        try:
            with self._lock:
                self._records.append(dict(record))
        except Exception as exc:  # pragma: no cover
            raise PersistenceError("Failed to persist trusted context") from exc

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)
