"""Structured agent actions and their canonical encoding.

Agents in this testbed never send free text to the systems they act on. Every
step is a structured action (tool name plus typed arguments), the form an
authorization gateway sees and logs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

INTERNAL_DOMAIN = "corp.internal"
# External domains the organization allowlists for email and document sharing.
PARTNER_DOMAINS = ("partner.com", "fulfil.io", "audit-firm.com")


def is_external(domain: str) -> bool:
    return domain != INTERNAL_DOMAIN


@dataclass
class Action:
    tool: str
    args: dict = field(default_factory=dict)
    agent: str = "root"
    step: int = -1

    def to_dict(self) -> dict:
        return {"step": self.step, "agent": self.agent, "tool": self.tool, "args": self.args}

    def canonical(self) -> bytes:
        """Deterministic JSON bytes (sorted keys, no whitespace) used for hashing."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def describe(self) -> str:
        """One readable line, used for logs and for the optional LLM monitor."""
        args = ", ".join(f"{k}={v}" for k, v in sorted(self.args.items()))
        return f"[{self.step:03d}] {self.agent}: {self.tool}({args})"
