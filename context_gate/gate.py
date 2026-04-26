"""ContextIntegrityGate orchestration pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonicalization import canonicalize_value, normalize_string
from .config import DEFAULT_GATE_CONFIG, GateConfig
from .exceptions import ContextRejection
from .policy import PolicyEngine, evaluate_default_policy
from .store import TrustedContextStore
from .types import Decision, GateIssue, GateResult
from .validation import ValidationRule, validate_envelope_schema


@dataclass(frozen=True)
class FieldSpec:
    """Declarative field-level canonicalization constraints."""

    name: str
    type: type
    required: bool = True
    allowed_values: set[Any] | None = None

    def canonicalize(self, value: Any, config: GateConfig) -> Any:
        if value is None:
            if self.required:
                raise ContextRejection(f"Missing required field: {self.name}")
            return None

        if self.type is str:
            output = normalize_string(value, config.canonicalization)
        elif self.type is int:
            output = int(value)
        elif self.type is float:
            output = float(value)
        elif self.type is bool:
            if isinstance(value, bool):
                output = value
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "1", "yes"}:
                    output = True
                elif lowered in {"false", "0", "no"}:
                    output = False
                else:
                    raise ContextRejection(f"Cannot coerce {value!r} to bool")
            else:
                raise ContextRejection(f"Cannot coerce {value!r} to bool")
        elif isinstance(value, self.type):
            output = value
        else:
            raise ContextRejection(
                f"Field {self.name!r} expected type {self.type.__name__}, got {type(value).__name__}"
            )

        if self.allowed_values is not None and output not in self.allowed_values:
            allowed = ", ".join(sorted(map(str, self.allowed_values)))
            raise ContextRejection(f"Field {self.name!r} must be one of {allowed}")

        return output


class ContextIntegrityGate:
    """Deterministic, zero-trust intake pipeline."""

    def __init__(
        self,
        field_specs: list[FieldSpec],
        validation_rules: list[ValidationRule],
        policy_engine: PolicyEngine,
        store: TrustedContextStore,
        config: GateConfig = DEFAULT_GATE_CONFIG,
    ) -> None:
        self._field_specs = {spec.name: spec for spec in field_specs}
        self._validation_rules = validation_rules
        self._policy_engine = policy_engine
        self._store = store
        self._config = config

    def process(self, raw_context: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self.evaluate(raw_context)
        if result.decision == Decision.REJECT:
            descriptions = "; ".join(f"{i.code}: {i.message}" for i in result.issues)
            raise ContextRejection(descriptions or "Context rejected")
        if result.decision == Decision.ACCEPT:
            self._store.persist(result.canonical_context)
        return result.canonical_context

    def evaluate(self, raw_context: Mapping[str, Any]) -> GateResult:
        issues: list[GateIssue] = []
        canonical = self._canonicalize(raw_context)

        try:
            fully_canonical = canonicalize_value(
                canonical,
                string_config=self._config.canonicalization,
                limits=self._config.limits,
            )
            if not isinstance(fully_canonical, dict):
                raise ContextRejection("Top-level context must be an object")
        except ContextRejection as exc:
            issues.append(GateIssue(code="E_CANONICALIZE", message=str(exc), path="/", severity="error"))
            fully_canonical = {}

        issues.extend(validate_envelope_schema(fully_canonical, self._config.schema))

        for rule in self._validation_rules:
            try:
                rule.validate(fully_canonical)
            except ValueError as exc:
                issues.append(
                    GateIssue(
                        code="E_VALIDATION_RULE",
                        message=str(exc),
                        path="/",
                        severity="error",
                    )
                )

        policy_decision = self._policy_engine.enforce(fully_canonical)
        if not policy_decision.allowed:
            for reason in policy_decision.reasons:
                issues.append(GateIssue(code="E_POLICY", message=reason, path="/", severity="error"))
        issues.extend(evaluate_default_policy(fully_canonical, self._config.policy))

        decision = _issues_to_decision(issues)
        return GateResult(decision=decision, canonical_context=fully_canonical, issues=tuple(issues))

    def _canonicalize(self, raw_context: Mapping[str, Any]) -> dict[str, Any]:
        canonical: dict[str, Any] = dict(raw_context)
        for name, spec in self._field_specs.items():
            if spec.required and name not in raw_context:
                raise ContextRejection(f"Missing required field: {name}")
            if name in raw_context:
                canonical[name] = spec.canonicalize(raw_context[name], self._config)
        return canonical



def _issues_to_decision(issues: list[GateIssue]) -> Decision:
    if any(issue.severity == "error" for issue in issues):
        return Decision.REJECT
    if any(issue.severity == "warn" for issue in issues):
        return Decision.FLAG
    return Decision.ACCEPT
