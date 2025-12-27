# Context Integrity Gate (CIG)

A reference implementation of a **deterministic, zero-trust gate** that decides whether
incoming context is allowed to exist **before** it is stored or used by downstream systems
(e.g., analytics, policy engines, or LLM pipelines).

CIG is designed to make context handling **boring, explainable, and reproducible**.

---

## Why this exists

Modern systems fail when untrusted or inconsistent context enters the pipeline:
- silent data corruption
- contradictions between fields
- unsafe payloads leaking into prompts
- downstream logic forced to “guess” validity

CIG pushes validation and policy enforcement **upstream** so downstream components can rely on a stronger integrity guarantee.

---

## What this does

- **Zero-trust intake**: all external input is untrusted by default
- **Canonicalization**: normalizes context into a deterministic internal form
- **Validation**: enforces schema and logical constraints
- **Policy enforcement**: blocks or flags unsafe / disallowed context
- **Deterministic decision**: outputs a clear **ACCEPT / FLAG / REJECT**
- **Traceability**: produces a stable fingerprint (hash) and audit-friendly output

---

## What this is NOT

- Not an AI model
- Not probabilistic
- Not production-ready software
- Not a complete governance platform

This project focuses on **correctness, clarity, and system guarantees**.

---

## How to run

### Requirements
- Python 3.9+

### Steps
1. Open a terminal (PowerShell on Windows, Terminal on macOS/Linux)
2. Navigate to the folder containing `cig.py`
3. Run the gate with a JSON file:

```bash
python cig.py --input-file input.json
