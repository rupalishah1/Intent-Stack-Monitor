"""Append-only, SHA-256 hash-chained evidence ledger.

Monitors read the session from the ledger rather than from the agent, so the
history they judge is tamper-evident: changing, dropping or reordering any
entry breaks every hash after it.
"""
from __future__ import annotations

import hashlib

from .actions import Action

GENESIS = "0" * 64


def _link(prev_hash: str, payload: bytes) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + payload).hexdigest()


class Ledger:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, action: Action) -> str:
        prev = self.head
        digest = _link(prev, action.canonical())
        self.entries.append({"action": action, "prev": prev, "hash": digest})
        return digest

    def verify(self) -> bool:
        prev = GENESIS
        for entry in self.entries:
            if entry["prev"] != prev or _link(prev, entry["action"].canonical()) != entry["hash"]:
                return False
            prev = entry["hash"]
        return True

    def actions(self) -> list[Action]:
        return [e["action"] for e in self.entries]
