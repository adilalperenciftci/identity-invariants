from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from identity_invariants.adapters.entra import (
    EntraGateConfig,
    EntraObservationRequest,
    HttpObservation,
    evaluate_entra_gate,
    observe_entra_case,
)
from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import EvidenceWriter
from identity_invariants.vectors.generator import TestCase as InvariantCase


TENANT_ID = "11111111-1111-4111-8111-111111111111"
APPLICATION_ID = "22222222-2222-4222-8222-222222222222"


def _config(request_ceiling: int = 2) -> EntraGateConfig:
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
        request_ceiling=request_ceiling,
        run_label="task9-gated-observation",
    )


def _case(index: int = 1) -> InvariantCase:
    return InvariantCase(
        id=f"wif-live-observe-{index}",
        rule_id="WIF-MATCH-001",
        kind="observe",
        source_case="wif-exact-tuple-match",
        seed=20261030,
    )


class FakeTransport:
    def __init__(self, response: HttpObservation) -> None:
        self.response = response
        self.requests: list[EntraObservationRequest] = []

    def send(self, request: EntraObservationRequest) -> HttpObservation:
        self.requests.append(request)
        return self.response


class FailingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, request: EntraObservationRequest) -> HttpObservation:
        self.calls += 1
        raise OSError("response body must never retain this detail")


def _passed_gate(request_ceiling: int = 2):
    result = evaluate_entra_gate(_config(request_ceiling))
    assert result.passed_gate is not None
    return result.passed_gate


def test_observer_persists_only_bounded_response_metadata(tmp_path: Path) -> None:
    response = HttpObservation(
        status_code=400,
        headers={"x-ms-request-id": "33333333-3333-4333-8333-333333333333"},
        body=json.dumps(
            {
                "error": "invalid_client",
                "error_description": "must-not-be-persisted",
                "access_token": "header.payload.signature",
            }
        ).encode(),
        elapsed_ms=125,
    )
    transport = FakeTransport(response)

    record = observe_entra_case(_case(), _passed_gate(), transport)
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    writer.append(record)

    assert len(transport.requests) == 1
    assert record.outcome == "observe"
    assert record.reason is ReasonCode.OBSERVATION_RECORDED
    assert record.metadata == {
        "run_label": "task9-gated-observation",
        "authority_host": "login.microsoftonline.com",
        "request_ordinal": 1,
        "status_code": 400,
        "error_code": "invalid_client",
        "correlation_id": "33333333-3333-4333-8333-333333333333",
        "elapsed_ms": 125,
    }
    persisted = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8")
    assert "must-not-be-persisted" not in persisted
    assert "header.payload.signature" not in persisted


def test_request_ceiling_stops_before_transport_call() -> None:
    response = HttpObservation(400, {}, b'{"error":"invalid_client"}', 1)
    transport = FakeTransport(response)
    gate = _passed_gate(request_ceiling=1)

    first = observe_entra_case(_case(1), gate, transport)
    second = observe_entra_case(_case(2), gate, transport)

    assert first.outcome == "observe"
    assert second.outcome == "skip"
    assert second.reason is ReasonCode.REQUEST_CEILING_REACHED
    assert second.metadata["network_request_count"] == 1
    assert len(transport.requests) == 1


def test_unbounded_or_malformed_response_is_inconclusive() -> None:
    oversized = FakeTransport(HttpObservation(400, {}, b"x" * 65537, 1))
    malformed = FakeTransport(HttpObservation(400, {}, b"{}", 1))
    duplicate_correlation = FakeTransport(
        HttpObservation(
            400,
            {
                "X-MS-Request-ID": "33333333-3333-4333-8333-333333333333",
                "x-ms-request-id": "44444444-4444-4444-8444-444444444444",
            },
            b'{"error":"invalid_client"}',
            1,
        )
    )

    oversized_record = observe_entra_case(_case(1), _passed_gate(), oversized)
    malformed_record = observe_entra_case(_case(2), _passed_gate(), malformed)
    duplicate_record = observe_entra_case(
        _case(3), _passed_gate(), duplicate_correlation
    )

    assert oversized_record.outcome == "inconclusive"
    assert oversized_record.reason is ReasonCode.RESPONSE_INVALID
    assert malformed_record.outcome == "inconclusive"
    assert malformed_record.reason is ReasonCode.RESPONSE_INVALID
    assert duplicate_record.reason is ReasonCode.RESPONSE_INVALID


def test_response_numeric_fields_require_integer_types() -> None:
    float_status = FakeTransport(
        HttpObservation(400.0, {}, b'{"error":"invalid_client"}', 1)
    )
    float_elapsed = FakeTransport(
        HttpObservation(400, {}, b'{"error":"invalid_client"}', 1.0)
    )

    status_record = observe_entra_case(_case(1), _passed_gate(), float_status)
    elapsed_record = observe_entra_case(_case(2), _passed_gate(), float_elapsed)

    assert status_record.reason is ReasonCode.RESPONSE_INVALID
    assert elapsed_record.reason is ReasonCode.RESPONSE_INVALID


def test_transport_failure_is_redacted() -> None:
    transport = FailingTransport()

    record = observe_entra_case(_case(), _passed_gate(), transport)

    assert transport.calls == 1
    assert record.outcome == "inconclusive"
    assert record.reason is ReasonCode.TRANSPORT_FAILED
    assert "detail" not in record.metadata


def test_closed_gate_records_skip_without_network_call() -> None:
    result = evaluate_entra_gate(replace(_config(), tenant_id=None))
    transport = FailingTransport()

    record = result.skip_record(_case())

    assert record.outcome == "skip"
    assert record.metadata["network_request_count"] == 0
    assert transport.calls == 0


def test_input_digest_binds_the_allowed_authority_host() -> None:
    response = HttpObservation(400, {}, b'{"error":"invalid_client"}', 1)
    primary = _passed_gate()
    alternate_result = evaluate_entra_gate(
        replace(
            _config(),
            authority_host="login.example.test",
            allowed_authority_hosts=frozenset({"login.example.test"}),
        )
    )
    assert alternate_result.passed_gate is not None

    primary_record = observe_entra_case(
        _case(1), primary, FakeTransport(response)
    )
    alternate_record = observe_entra_case(
        _case(1), alternate_result.passed_gate, FakeTransport(response)
    )

    assert primary_record.input_digest != alternate_record.input_digest
