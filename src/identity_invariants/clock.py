"""Injected clocks and bounded replay stores."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from identity_invariants.canonical import digest_identifier


class Clock(Protocol):
    def now(self) -> int:
        """Return a NumericDate-compatible timestamp."""


@dataclass(frozen=True, slots=True)
class FrozenClock:
    value: int

    def now(self) -> int:
        return self.value


@dataclass(slots=True)
class ReplayStore:
    """Bounded active-digest set controlled entirely by an injected time."""

    _entries: dict[tuple[str, str], int] = field(default_factory=dict)

    def _prune(self, now: int) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def consume(self, namespace: str, digest: str, expires_at: int, now: int) -> bool:
        self._prune(now)
        key = (namespace, digest)
        if expires_at <= now or key in self._entries:
            return False
        self._entries[key] = expires_at
        return True


@dataclass(slots=True)
class NonceStore:
    """One-use nonce store that persists only domain-separated digests."""

    _entries: dict[tuple[str, str], int] = field(default_factory=dict)

    def _prune(self, now: int) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def remember(self, namespace: str, nonce: str, expires_at: int) -> None:
        digest = digest_identifier(namespace, nonce)
        self._entries[(namespace, digest)] = expires_at

    def consume(self, namespace: str, nonce: str, now: int) -> bool:
        self._prune(now)
        key = (namespace, digest_identifier(namespace, nonce))
        if key not in self._entries:
            return False
        del self._entries[key]
        return True
