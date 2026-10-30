from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from identity_invariants.adapters.entra import (
    EntraGateConfig,
    PassedGate,
    evaluate_entra_gate,
    record_closed_environment,
)
from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import EvidenceWriter, verify_manifest
from identity_invariants.vectors.generator import TestCase as InvariantCase


TENANT_ID = "11111111-1111-4111-8111-111111111111"
APPLICATION_ID = "22222222-2222-4222-8222-222222222222"


def _config() -> EntraGateConfig:
    return EntraGateConfig(
        tenant_id=TENANT_ID,
        allowed_tenant_ids=frozenset({TENANT_ID}),
        application_id=APPLICATION_ID,
        application_is_disposable=True,
        authority_host="login.microsoftonline.com",
        allowed_authority_hosts=frozenset({"login.microsoftonline.com"}),
        fic_identifier="fic-identity-invariants",
        directory_roles=frozenset(),
        redaction_test_passed=True,
        request_ceiling=2,
        run_label="task9-gated-observation",
    )


def _case() -> InvariantCase:
    return InvariantCase(
        id="wif-match-observe-case",
        rule_id="WIF-MATCH-001",
        kind="observe",
        source_case="wif-exact-tuple-match",
        seed=20261030,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"tenant_id": None}, ReasonCode.TENANT_CONTEXT_MISSING),
        (
            {"allowed_tenant_ids": frozenset()},
            ReasonCode.TENANT_CONTEXT_NOT_ALLOWED,
        ),
        ({"application_id": None}, ReasonCode.DISPOSABLE_APPLICATION_MISSING),
        (
            {"application_is_disposable": False},
            ReasonCode.DISPOSABLE_APPLICATION_MISSING,
        ),
        ({"authority_host": None}, ReasonCode.AUTHORITY_HOST_NOT_ALLOWED),
        (
            {"allowed_authority_hosts": frozenset()},
            ReasonCode.AUTHORITY_HOST_NOT_ALLOWED,
        ),
        ({"fic_identifier": None}, ReasonCode.FIC_IDENTIFIER_MISSING),
        (
            {"directory_roles": frozenset({"Global Administrator"})},
            ReasonCode.DIRECTORY_ROLE_NOT_MINIMAL,
        ),
        ({"redaction_test_passed": False}, ReasonCode.REDACTION_PROBE_FAILED),
        ({"request_ceiling": 0}, ReasonCode.REQUEST_CEILING_INVALID),
        ({"request_ceiling": 9}, ReasonCode.REQUEST_CEILING_INVALID),
        ({"run_label": None}, ReasonCode.RUN_LABEL_MISSING),
    ],
)
def test_gate_fails_closed_for_each_prerequisite(
    change: dict[str, object], reason: ReasonCode
) -> None:
    result = evaluate_entra_gate(replace(_config(), **change))

    assert result.outcome == "skip"
    assert result.passed_gate is None
    assert reason in result.reasons
    assert result.request_permitted is False


def test_gate_passes_only_with_exact_bounded_context() -> None:
    result = evaluate_entra_gate(_config())

    assert result.outcome == "pass"
    assert result.reasons == ()
    assert result.request_permitted is True
    assert isinstance(result.passed_gate, PassedGate)
    assert result.passed_gate.endpoint == (
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    )


def test_skip_record_is_redacted_and_sealable(tmp_path: Path) -> None:
    result = evaluate_entra_gate(
        replace(
            _config(),
            tenant_id=None,
            application_id=None,
            fic_identifier=None,
            run_label=None,
        )
    )
    record = result.skip_record(_case())
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")

    writer.append(record)
    manifest = writer.seal()

    assert record.outcome == "skip"
    assert record.evidence_class == "entra-observation"
    assert record.reason is ReasonCode.TENANT_CONTEXT_MISSING
    assert record.metadata["network_request_count"] == 0
    assert "tenant_id" not in record.metadata
    verify_manifest(manifest.path)


def test_gate_rejects_non_uuid_context_and_unbounded_labels() -> None:
    malformed = evaluate_entra_gate(
        replace(
            _config(),
            tenant_id="not-a-tenant",
            application_id="not-an-application",
            run_label="contains spaces",
        )
    )

    assert malformed.outcome == "skip"
    assert ReasonCode.TENANT_CONTEXT_NOT_ALLOWED in malformed.reasons
    assert ReasonCode.DISPOSABLE_APPLICATION_MISSING in malformed.reasons
    assert ReasonCode.RUN_LABEL_MISSING in malformed.reasons


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"tenant_id": 7}, ReasonCode.TENANT_CONTEXT_NOT_ALLOWED),
        ({"application_id": 7}, ReasonCode.DISPOSABLE_APPLICATION_MISSING),
        ({"authority_host": 7}, ReasonCode.AUTHORITY_HOST_NOT_ALLOWED),
        ({"fic_identifier": 7}, ReasonCode.FIC_IDENTIFIER_MISSING),
        ({"request_ceiling": "2"}, ReasonCode.REQUEST_CEILING_INVALID),
        ({"run_label": 7}, ReasonCode.RUN_LABEL_MISSING),
    ],
)
def test_gate_fails_closed_for_runtime_type_mismatches(
    change: dict[str, object], reason: ReasonCode
) -> None:
    result = evaluate_entra_gate(replace(_config(), **change))

    assert result.outcome == "skip"
    assert reason in result.reasons


def test_closed_environment_record_is_distinct_and_sealed(tmp_path: Path) -> None:
    ledger = tmp_path / "ubuntu-entra.jsonl"

    manifest = record_closed_environment(ledger, "ubuntu-lab")

    verify_manifest(manifest)
    document = ledger.read_text(encoding="utf-8")
    assert '"case_id":"wif-live-gate-ubuntu-lab"' in document
    assert '"network_request_count":0' in document
