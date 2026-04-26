"""Deterministic validation primitives and schema checks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .config import SchemaConfig
from .types import GateIssue


@dataclass
class ValidationRule:
    name: str
    check: Callable[[Mapping[str, Any]], bool]
    message: str

    def validate(self, context: Mapping[str, Any]) -> None:
        if not self.check(context):
            raise ValueError(f"Validation failed for {self.name}: {self.message}")


def estimate_json_bytes(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def validate_envelope_schema(ctx: Mapping[str, Any], schema_config: SchemaConfig) -> list[GateIssue]:
    issues: list[GateIssue] = []

    def err(code: str, msg: str, path: str) -> None:
        issues.append(GateIssue(code=code, message=msg, path=path, severity="error"))

    def warn(code: str, msg: str, path: str) -> None:
        issues.append(GateIssue(code=code, message=msg, path=path, severity="warn"))

    if estimate_json_bytes(ctx) > schema_config.max_bytes_estimate:
        err("E_SIZE", "Context too large", "/")

    sv = ctx.get("schema_version")
    if sv is None:
        err("E_SCHEMA_VERSION_MISSING", "Missing schema_version", "/schema_version")
    elif not isinstance(sv, int) or isinstance(sv, bool) or sv < 1:
        err("E_SCHEMA_VERSION_INVALID", "schema_version must be int >= 1", "/schema_version")

    ct = ctx.get("context_type")
    if not isinstance(ct, str) or not ct.strip():
        err("E_CONTEXT_TYPE_INVALID", "context_type must be non-empty string", "/context_type")

    subject = ctx.get("subject")
    if not isinstance(subject, dict):
        err("E_SUBJECT_TYPE", "subject must be object", "/subject")
    else:
        subject_id = subject.get("id")
        subject_kind = subject.get("kind")
        if not isinstance(subject_id, str) or not subject_id.strip():
            err("E_SUBJECT_ID", "subject.id must be non-empty string", "/subject/id")
        if not isinstance(subject_kind, str) or not subject_kind.strip():
            err("E_SUBJECT_KIND", "subject.kind must be non-empty string", "/subject/kind")

    attributes = ctx.get("attributes")
    if not isinstance(attributes, dict):
        err("E_ATTRIBUTES_TYPE", "attributes must be object", "/attributes")

    if "claims" in ctx and not isinstance(ctx["claims"], list):
        err("E_CLAIMS_TYPE", "claims must be array", "/claims")

    if "metadata" in ctx and not isinstance(ctx["metadata"], dict):
        err("E_METADATA_TYPE", "metadata must be object", "/metadata")

    for key in ctx.keys():
        if key not in schema_config.allowed_top_level_keys:
            warn("W_UNKNOWN_TOP_KEY", f"Unknown top-level key '{key}'", f"/{key}")

    return issues
