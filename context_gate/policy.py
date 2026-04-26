"""Policy enforcement for Context Integrity Gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .config import PolicyConfig
from .types import GateIssue, PolicyDecision


@dataclass
class PolicyEngine:
    checks: list[Callable[[Mapping[str, Any]], str | None]] = field(default_factory=list)

    def enforce(self, context: Mapping[str, Any]) -> PolicyDecision:
        reasons: list[str] = []
        for check in self.checks:
            reason = check(context)
            if reason:
                reasons.append(reason)
        return PolicyDecision(allowed=not reasons, reasons=reasons)


def evaluate_default_policy(ctx: Mapping[str, Any], config: PolicyConfig) -> list[GateIssue]:
    issues: list[GateIssue] = []

    def err(code: str, message: str, path: str) -> None:
        issues.append(GateIssue(code=code, message=message, path=path, severity="error"))

    def warn(code: str, message: str, path: str) -> None:
        issues.append(GateIssue(code=code, message=message, path=path, severity="warn"))

    context_type = ctx.get("context_type")
    if isinstance(context_type, str) and context_type in config.blocked_context_types:
        err("E_BLOCKED_TYPE", f"context_type '{context_type}' is blocked", "/context_type")

    def key_looks_secret(key: str) -> bool:
        lowered = key.lower()
        if lowered in config.secret_key_hints:
            return True
        return any(pattern.search(key) for pattern in config.secret_key_patterns)

    def value_looks_secret(value: str) -> bool:
        return any(pattern.search(value) for pattern in config.secret_value_patterns)

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key in sorted(node.keys()):
                child_path = f"{path}/{key}" if path else f"/{key}"
                if key_looks_secret(key):
                    err("E_SECRET_KEY", f"Secret-like key '{key}' is not allowed", child_path)
                walk(node[key], child_path)
        elif isinstance(node, list):
            for idx, child in enumerate(node):
                child_path = f"{path}/{idx}" if path else f"/{idx}"
                walk(child, child_path)
        elif isinstance(node, str) and value_looks_secret(node):
            warn("W_SECRET_VALUE", "Value looks like a secret/token", path or "/")

    walk(ctx, "")
    return issues
