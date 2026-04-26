"""Shared types for Context Integrity Gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Decision(Enum):
    ACCEPT = auto()
    REJECT = auto()
    FLAG = auto()


@dataclass(frozen=True)
class GateIssue:
    code: str
    message: str
    path: str = "/"
    severity: str = "error"


@dataclass(frozen=True)
class GateResult:
    decision: Decision
    canonical_context: dict[str, Any]
    issues: tuple[GateIssue, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
