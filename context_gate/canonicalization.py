"""Deterministic canonicalization helpers."""

from __future__ import annotations

import math
import unicodedata
from typing import Any

from .config import CanonicalizationConfig, SafetyLimits
from .exceptions import ContextRejection


def normalize_string(value: Any, config: CanonicalizationConfig) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    if not isinstance(value, str):
        raise ContextRejection(f"Expected string-like value, got {type(value).__name__}")

    out = unicodedata.normalize(config.normalize_unicode_form, value)
    if config.strip_strings:
        out = out.strip()
    if config.collapse_whitespace:
        out = " ".join(out.split())
    if config.lowercase_strings:
        out = out.lower()
    return out


def _check_non_finite_float(value: float) -> None:
    if math.isnan(value) or math.isinf(value):
        raise ContextRejection("Non-finite float values are not allowed")


def canonicalize_value(
    value: Any,
    *,
    string_config: CanonicalizationConfig,
    limits: SafetyLimits,
    path: str = "/",
    depth: int = 0,
    state: dict[str, int] | None = None,
) -> Any:
    if state is None:
        state = {"nodes": 0}

    state["nodes"] += 1
    if state["nodes"] > limits.max_total_nodes:
        raise ContextRejection(f"Too many nodes at {path}")
    if depth > limits.max_depth:
        raise ContextRejection(f"Max depth exceeded at {path}")

    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value

    if isinstance(value, float):
        _check_non_finite_float(value)
        return float(value)

    if isinstance(value, str) or isinstance(value, bytes):
        out = normalize_string(value, string_config)
        if len(out) > limits.max_string_length:
            raise ContextRejection(f"String too long at {path}")
        return out

    if isinstance(value, list):
        if len(value) > limits.max_list_length:
            raise ContextRejection(f"List too long at {path}")
        return [
            canonicalize_value(
                item,
                string_config=string_config,
                limits=limits,
                path=f"{path.rstrip('/')}/{i}",
                depth=depth + 1,
                state=state,
            )
            for i, item in enumerate(value)
        ]

    if isinstance(value, dict):
        if len(value) > limits.max_keys_per_object:
            raise ContextRejection(f"Too many keys at {path}")

        canonical_items: list[tuple[str, Any]] = []
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContextRejection(f"Non-string key at {path}: {key!r}")
            canonical_key = normalize_string(key, string_config)
            canonical_items.append((canonical_key, child))

        output: dict[str, Any] = {}
        for key, child in sorted(canonical_items, key=lambda it: it[0]):
            child_path = f"{path.rstrip('/')}/{key}"
            output[key] = canonicalize_value(
                child,
                string_config=string_config,
                limits=limits,
                path=child_path,
                depth=depth + 1,
                state=state,
            )
        return output

    raise ContextRejection(f"Unsupported type at {path}: {type(value).__name__}")
