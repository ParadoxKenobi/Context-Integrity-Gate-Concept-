"""Factory helpers for default Context Integrity Gate configuration."""

from __future__ import annotations

from typing import Any, Mapping

from .gate import ContextIntegrityGate, FieldSpec
from .policy import PolicyEngine
from .store import TrustedContextStore
from .validation import ValidationRule


def build_default_gate() -> ContextIntegrityGate:
    field_specs = [
        FieldSpec("schema_version", int, required=True),
        FieldSpec("context_type", str, required=True),
        FieldSpec("subject", dict, required=True),
        FieldSpec("attributes", dict, required=True),
        FieldSpec("metadata", dict, required=False),
        FieldSpec("claims", list, required=False),
    ]

    validation_rules = [
        ValidationRule(
            name="subject-is-object",
            check=lambda ctx: isinstance(ctx.get("subject"), dict),
            message="subject must be an object",
        ),
    ]

    def reject_archived(context: Mapping[str, Any]) -> str | None:
        metadata = context.get("metadata")
        if isinstance(metadata, dict) and metadata.get("archived") is True:
            return "archived contexts are not accepted"
        return None

    policy_engine = PolicyEngine(checks=[reject_archived])
    return ContextIntegrityGate(
        field_specs=field_specs,
        validation_rules=validation_rules,
        policy_engine=policy_engine,
        store=TrustedContextStore(),
    )
