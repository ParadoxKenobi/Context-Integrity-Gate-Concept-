# Context Integrity Gate (Concept)

Context Integrity Gate is a deterministic front-door system that decides whether incoming context can be trusted before it is stored or used downstream. Every input—user data, files, API payloads, or historical records—is treated as untrusted until it passes the gate.

## What this repository now provides

A modular Python implementation of the gate split across focused files, instead of one large script:

- `context_gate/config.py` — defaults for canonicalization, schema, policy, and safety limits.
- `context_gate/canonicalization.py` — deterministic normalization and deep canonicalization.
- `context_gate/validation.py` — envelope/schema validation and rule abstraction.
- `context_gate/policy.py` — deterministic policy checks (blocked types, secret-like keys/values).
- `context_gate/store.py` — thread-safe trusted context persistence.
- `context_gate/gate.py` — orchestration pipeline (`evaluate` + `process`) and `FieldSpec`.
- `context_gate/factory.py` — default gate construction.

This keeps concerns separated and easier to evolve like a production-grade context pipeline.

## Deterministic lifecycle

1. Canonicalize raw context into a stable representation.
2. Validate required envelope structure and explicit rules.
3. Enforce policy before persistence.
4. Emit deterministic decision (`ACCEPT`, `FLAG`, `REJECT`).
5. Persist only accepted context.

## Quick start

```python
from context_gate import build_default_gate, ContextRejection

gate = build_default_gate()

payload = {
    "schema_version": 1,
    "context_type": "profile",
    "subject": {"id": "u1", "kind": "user"},
    "attributes": {"name": "  Jane   Doe  "},
}

try:
    trusted = gate.process(payload)
    print("Trusted:", trusted)
except ContextRejection as exc:
    print("Rejected:", exc)
```

## Tests

```bash
python -m pytest
```
