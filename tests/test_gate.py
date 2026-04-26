import pytest

from context_gate import (
    ContextIntegrityGate,
    ContextRejection,
    Decision,
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
            "schema_version": 1,
            "context_type": "Profile",
            "subject": {"id": "U1", "kind": "User"},
            "attributes": {"name": " Alice   Doe "},
            "metadata": {"source_app": "Demo"},
        }
    )

    assert trusted == {
        "schema_version": 1,
        "context_type": "profile",
        "subject": {"id": "u1", "kind": "user"},
        "attributes": {"name": "alice doe"},
        "metadata": {"source_app": "demo"},
    }
    assert gate._store.all() == [trusted]


def test_validation_failure_blocks_persistence():
    gate = build_default_gate()

    with pytest.raises(ContextRejection) as excinfo:
        gate.process(
            {
                "schema_version": 0,
                "context_type": "profile",
                "subject": {"id": "u1", "kind": "user"},
                "attributes": {"x": "y"},
            }
        )

    assert "E_SCHEMA_VERSION_INVALID" in str(excinfo.value)
    assert gate._store.all() == []


def test_policy_rejection_explains_reason():
    gate = build_default_gate()

    with pytest.raises(ContextRejection) as excinfo:
        gate.process(
            {
                "schema_version": 1,
                "context_type": "profile",
                "subject": {"id": "u1", "kind": "user"},
                "attributes": {"x": "y"},
                "metadata": {"archived": True},
            }
        )

    assert "archived contexts are not accepted" in str(excinfo.value)
    assert gate._store.all() == []


def test_flag_secret_like_value_on_evaluate():
    gate = build_default_gate()

    result = gate.evaluate(
        {
            "schema_version": 1,
            "context_type": "profile",
            "subject": {"id": "u1", "kind": "user"},
            "attributes": {"note": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
        }
    )

    assert result.decision == Decision.FLAG
    assert any(issue.code == "W_SECRET_VALUE" for issue in result.issues)




def test_flag_process_does_not_persist():
    gate = build_default_gate()

    trusted = gate.process(
        {
            "schema_version": 1,
            "context_type": "profile",
            "subject": {"id": "u1", "kind": "user"},
            "attributes": {"note": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
        }
    )

    assert trusted["attributes"]["note"].startswith("sk-")
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

    trusted = gate.process(
        {
            "record_id": "RID-1",
            "payload_version": "2",
            "schema_version": 1,
            "context_type": "custom",
            "subject": {"id": "u1", "kind": "user"},
            "attributes": {},
        }
    )
    assert trusted["record_id"] == "rid-1"
    assert trusted["payload_version"] == 2

    with pytest.raises(ContextRejection):
        gate.process(
            {
                "record_id": "RID-1",
                "payload_version": "5",
                "schema_version": 1,
                "context_type": "custom",
                "subject": {"id": "u1", "kind": "user"},
                "attributes": {},
            }
        )
