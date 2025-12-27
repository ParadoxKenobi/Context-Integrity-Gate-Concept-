import pytest

from context_gate import (
    ContextIntegrityGate,
    ContextRejection,
    FieldSpec,
    PolicyEngine,
    TrustedContextStore,
    ValidationRule,
    build_default_gate,
)


def test_successful_pipeline_persists_canonical_context():
    gate = build_default_gate()

    trusted = gate.process(
        {
            "user_id": " Alice ",
            "email": "Alice@example.org",
            "age": "30",
            "active": "true",
            "country": "US",
        }
    )

    assert trusted == {
        "user_id": "alice",
        "email": "alice@example.org",
        "age": 30,
        "active": True,
        "country": "us",
    }
    assert gate._store.all() == [trusted]


def test_validation_failure_blocks_persistence():
    gate = build_default_gate()

    with pytest.raises(ContextRejection) as excinfo:
        gate.process({"user_id": "ab", "email": "bad-email", "age": 200})

    assert "Validation failed" in str(excinfo.value)
    assert gate._store.all() == []


def test_policy_rejection_explains_reason():
    gate = build_default_gate()

    with pytest.raises(ContextRejection) as excinfo:
        gate.process({"user_id": "alice", "email": "user@example.com", "age": 25})

    assert "example.com addresses are not permitted" in str(excinfo.value)
    assert gate._store.all() == []


def test_custom_gate_with_required_optional_fields():
    field_specs = [
        FieldSpec("record_id", str, required=True),
        FieldSpec("payload_version", int, required=True),
        FieldSpec("comment", str, required=False),
    ]
    validation_rules = [
        ValidationRule(
            name="payload-version-range",
            check=lambda ctx: 1 <= ctx["payload_version"] <= 3,
            message="payload_version must be 1-3",
        )
    ]
    policy_engine = PolicyEngine(checks=[lambda ctx: None])
    store = TrustedContextStore()
    gate = ContextIntegrityGate(field_specs, validation_rules, policy_engine, store)

    trusted = gate.process({"record_id": "RID-1", "payload_version": "2"})
    assert trusted == {"record_id": "rid-1", "payload_version": 2}
    assert gate._store.all() == [trusted]

    with pytest.raises(ContextRejection):
        gate.process({"record_id": "RID-1", "payload_version": "5"})
    assert gate._store.all() == [trusted]
