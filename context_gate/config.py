"""Configuration defaults for the Context Integrity Gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Pattern
import re


@dataclass(frozen=True)
class CanonicalizationConfig:
    normalize_unicode_form: str = "NFKC"
    lowercase_strings: bool = True
    strip_strings: bool = True
    collapse_whitespace: bool = True


@dataclass(frozen=True)
class SafetyLimits:
    max_depth: int = 12
    max_total_nodes: int = 25_000
    max_keys_per_object: int = 250
    max_list_length: int = 2_000
    max_string_length: int = 20_000


@dataclass(frozen=True)
class PolicyConfig:
    blocked_context_types: frozenset[str] = frozenset({"credential_dump", "malware_config"})
    secret_key_hints: frozenset[str] = frozenset(
        {
            "password",
            "passwd",
            "pass",
            "secret",
            "api_key",
            "apikey",
            "token",
            "auth",
            "authorization",
            "bearer",
            "private_key",
            "ssh_key",
        }
    )
    secret_key_patterns: tuple[Pattern[str], ...] = (
        re.compile(r".*\\b(password|passwd|api[_-]?key|secret|token|private[_-]?key)\\b.*", re.IGNORECASE),
        re.compile(r"^authorization$", re.IGNORECASE),
    )
    secret_value_patterns: tuple[Pattern[str], ...] = (
        re.compile(r"^sk-[A-Za-z0-9]{20,}$"),
        re.compile(r"^[A-Za-z0-9_\-]{40,}$"),
        re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    )


@dataclass(frozen=True)
class SchemaConfig:
    max_bytes_estimate: int = 2_000_000
    allowed_top_level_keys: frozenset[str] = frozenset(
        {"schema_version", "context_type", "subject", "attributes", "metadata", "claims"}
    )


@dataclass(frozen=True)
class GateConfig:
    canonicalization: CanonicalizationConfig = field(default_factory=CanonicalizationConfig)
    limits: SafetyLimits = field(default_factory=SafetyLimits)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    schema: SchemaConfig = field(default_factory=SchemaConfig)


DEFAULT_GATE_CONFIG = GateConfig()
