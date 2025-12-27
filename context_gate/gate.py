"""Deterministic Context Integrity Gate implementation.

The gate performs canonicalization, rule-based validation, policy enforcement, and
safe persistence of trusted context objects. The code follows the conceptual design
from the project README and intentionally avoids probabilistic behavior.
"""
from __future__ import annotations

import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional


class ContextRejection(Exception):
    """Raised when context fails normalization, validation, or policy checks."""


class PersistenceError(Exception):
    """Raised when persistence of trusted context fails."""


@dataclass(frozen=True)
class FieldSpec:
    """Declarative specification for canonicalizing a single field."""

    name: str
    type: type
    required: bool = True
    allowed_values: Optional[Iterable[Any]] = None
    normalizer: Optional[Callable[[Any], Any]] = None

    def canonicalize(self, value: Any) -> Any:
        if value is None:
            if self.required:
                raise ContextRejection(f"Missing required field: {self.name}")
            return None

        if self.normalizer:
            value = self.normalizer(value)

        if self.type is str:
            value = _normalize_string(value)
        elif self.type in (int, float, bool):
            value = _coerce_number_or_bool(value, self.type)
        elif not isinstance(value, self.type):
            raise ContextRejection(
                f"Field {self.name!r} expected type {self.type.__name__}, got {type(value).__name__}"
            )

        if self.allowed_values is not None and value not in self.allowed_values:
            allowed_list = ", ".join(map(repr, self.allowed_values))
            raise ContextRejection(
                f"Field {self.name!r} must be one of: {allowed_list}; got {value!r}"
            )

        return value


def _normalize_string(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    if not isinstance(value, str):
        raise ContextRejection(f"Expected string-like value, got {type(value).__name__}")

    # Unicode NFC normalization, whitespace collapse, and lowercase for stability.
    normalized = unicodedata.normalize("NFC", value)
    collapsed = " ".join(normalized.split())
    return collapsed.lower()


def _coerce_number_or_bool(value: Any, target_type: type) -> Any:
    if target_type is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes"}:
                return True
            if lowered in {"false", "0", "no"}:
                return False
        raise ContextRejection(f"Cannot coerce {value!r} to bool")

    if isinstance(value, target_type):
        return value

    if isinstance(value, str):
        try:
            return target_type(value)
        except (TypeError, ValueError):
            pass

    raise ContextRejection(f"Cannot coerce {value!r} to {target_type.__name__}")


@dataclass
class ValidationRule:
    """Deterministic rule that must hold for trusted context."""

    name: str
    check: Callable[[Mapping[str, Any]], bool]
    message: str

    def validate(self, context: Mapping[str, Any]) -> None:
        if not self.check(context):
            raise ContextRejection(f"Validation failed for {self.name}: {self.message}")


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)


@dataclass
class PolicyEngine:
    """Applies policy checks before persistence."""

    checks: List[Callable[[Mapping[str, Any]], Optional[str]]] = field(
        default_factory=list
    )

    def enforce(self, context: Mapping[str, Any]) -> PolicyDecision:
        reasons: List[str] = []
        for check in self.checks:
            reason = check(context)
            if reason:
                reasons.append(reason)
        return PolicyDecision(allowed=not reasons, reasons=reasons)


class TrustedContextStore:
    """Thread-safe in-memory store for trusted context objects."""

    def __init__(self) -> None:
        self._records: List[Mapping[str, Any]] = []
        self._lock = threading.Lock()

    def persist(self, record: Mapping[str, Any]) -> None:
        try:
            with self._lock:
                self._records.append(dict(record))
        except Exception as exc:  # pragma: no cover - defensive guardrail
            raise PersistenceError("Failed to persist trusted context") from exc

    def all(self) -> List[Mapping[str, Any]]:
        with self._lock:
            return list(self._records)


class ContextIntegrityGate:
    """Deterministic context intake pipeline.

    1. Canonicalize raw input using field specs
    2. Validate using explicit rules
    3. Enforce policy decisions
    4. Persist trusted context
    """

    def __init__(
        self,
        field_specs: Iterable[FieldSpec],
        validation_rules: Iterable[ValidationRule],
        policy_engine: PolicyEngine,
        store: TrustedContextStore,
    ) -> None:
        self._field_specs: Dict[str, FieldSpec] = {spec.name: spec for spec in field_specs}
        self._validation_rules = list(validation_rules)
        self._policy_engine = policy_engine
        self._store = store

    def process(self, raw_context: Mapping[str, Any]) -> Mapping[str, Any]:
        canonical = self._canonicalize(raw_context)
        self._validate(canonical)
        decision = self._policy_engine.enforce(canonical)
        if not decision.allowed:
            raise ContextRejection(
                "; ".join(["Policy enforcement rejected context"] + decision.reasons)
            )
        self._store.persist(canonical)
        return canonical

    def _canonicalize(self, raw_context: Mapping[str, Any]) -> Dict[str, Any]:
        canonical: Dict[str, Any] = {}
        for name, spec in self._field_specs.items():
            if spec.required and name not in raw_context:
                raise ContextRejection(f"Missing required field: {name}")
            if name in raw_context:
                canonical[name] = spec.canonicalize(raw_context[name])
        return canonical

    def _validate(self, canonical_context: Mapping[str, Any]) -> None:
        for rule in self._validation_rules:
            rule.validate(canonical_context)


# Convenience factory for a simple example gate configuration.
def build_default_gate() -> ContextIntegrityGate:
    field_specs = [
        FieldSpec("user_id", str, required=True),
        FieldSpec("email", str, required=True),
        FieldSpec("age", int, required=True, normalizer=lambda v: int(_coerce_number_or_bool(v, int))),
        FieldSpec("active", bool, required=False, normalizer=lambda v: _coerce_number_or_bool(v, bool)),
        FieldSpec("country", str, required=False, allowed_values={"us", "ca", "uk", "de"}),
    ]

    validation_rules = [
        ValidationRule(
            name="age-range",
            check=lambda ctx: 0 <= ctx.get("age", -1) <= 120,
            message="Age must be between 0 and 120",
        ),
        ValidationRule(
            name="email-has-at",
            check=lambda ctx: "@" in ctx.get("email", ""),
            message="Email must contain @",
        ),
        ValidationRule(
            name="user-id-length",
            check=lambda ctx: len(ctx.get("user_id", "")) >= 3,
            message="User ID must be at least 3 characters",
        ),
    ]

    def block_disposable_email(context: Mapping[str, Any]) -> Optional[str]:
        if context.get("email", "").endswith("@example.com"):
            return "example.com addresses are not permitted"
        return None

    def require_country_for_inactive(context: Mapping[str, Any]) -> Optional[str]:
        if context.get("active") is False and not context.get("country"):
            return "country is required when active is false"
        return None

    policy_engine = PolicyEngine(checks=[block_disposable_email, require_country_for_inactive])
    store = TrustedContextStore()
    return ContextIntegrityGate(field_specs, validation_rules, policy_engine, store)
