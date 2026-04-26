"""Context Integrity Gate package."""

from .config import DEFAULT_GATE_CONFIG, GateConfig
from .exceptions import ContextRejection, PersistenceError
from .factory import build_default_gate
from .gate import ContextIntegrityGate, FieldSpec
from .policy import PolicyDecision, PolicyEngine
from .store import TrustedContextStore
from .types import Decision, GateIssue, GateResult
from .validation import ValidationRule

__all__ = [
    "ContextIntegrityGate",
    "ContextRejection",
    "Decision",
    "DEFAULT_GATE_CONFIG",
    "FieldSpec",
    "GateConfig",
    "GateIssue",
    "GateResult",
    "PersistenceError",
    "PolicyDecision",
    "PolicyEngine",
    "TrustedContextStore",
    "ValidationRule",
    "build_default_gate",
]
