# Context Integrity Gate (CIG)

A reference implementation of a deterministic, zero-trust gate that decides whether
incoming context is allowed to exist before it is stored or used by downstream systems.

## What this does
- Treats all input as untrusted
- Canonicalizes context into a deterministic form
- Enforces schema and policy rules
- Produces a clear ACCEPT / FLAG / REJECT decision
- Generates an audit fingerprint for traceability

## What this is NOT
- Not an AI model
- Not probabilistic
- Not production-ready software

This project focuses on correctness, clarity, and system guarantees.

## How to run

### Requirements
- Python 3.9+

### Steps
1. Open a terminal (PowerShell on Windows, Terminal on macOS/Linux)
2. Navigate to the folder containing `cig.py`
3. Run the gate with a JSON file:

```bash
python cig.py --input-file input.json
