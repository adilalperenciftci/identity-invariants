"""Closed-by-default adapters for bounded Entra observations."""

from __future__ import annotations

import argparse
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID

from identity_invariants.canonical import (
    JSONValue,
    digest_identifier,
    parse_json_object,
)
from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import EvidenceRecord, EvidenceWriter
from identity_invariants.vectors.generator import TestCase, canonical_digest


_MAX_REQUESTS = 8
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_ELAPSED_MS = 30_000
_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_FIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$")
_ERROR_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class EntraGateConfig:
    tenant_id: str | None
    allowed_tenant_ids: frozenset[str]
    application_id: str | None
    application_is_disposable: bool
    authority_host: str | None
    allowed_authority_hosts: frozenset[str]
    fic_identifier: str | None
    directory_roles: frozenset[str]
    redaction_test_passed: bool
    request_ceiling: int
    run_label: str | None


class _RequestBudget:
    __slots__ = ("_ceiling", "_lock", "_used")

    def __init__(self, ceiling: int) -> None:
        self._ceiling = ceiling
        self._used = 0
        self._lock = threading.Lock()

    def consume(self) -> int | None:
        with self._lock:
            if self._used >= self._ceiling:
                return None
            self._used += 1
            return self._used

    @property
    def used(self) -> int:
        with self._lock:
            return self._used


@dataclass(frozen=True, slots=True)
class PassedGate:
    tenant_id: str
    application_id: str
    authority_host: str
    fic_identifier: str
    run_label: str
    request_ceiling: int
    endpoint: str
    _budget: _RequestBudget = field(repr=False, compare=False)

    def consume_request(self) -> int | None:
        return self._budget.consume()

    @property
    def requests_used(self) -> int:
        return self._budget.used


@dataclass(frozen=True, slots=True)
class GateResult:
    outcome: Literal["pass", "skip"]
    reasons: tuple[ReasonCode, ...]
    passed_gate: PassedGate | None

    @property
    def request_permitted(self) -> bool:
        return self.passed_gate is not None

    def skip_record(self, case: TestCase) -> EvidenceRecord:
        if (
            self.outcome != "skip"
            or self.passed_gate is not None
            or not self.reasons
        ):
            raise RuntimeError(
                "a passed gate cannot produce a prerequisite skip record"
            )
        reason_values = [reason.value for reason in self.reasons]
        return EvidenceRecord(
            case_id=case.id,
            rule_id=case.rule_id,
            outcome="skip",
            reason=self.reasons[0],
            evidence_class="entra-observation",
            input_digest=canonical_digest(
                {
                    "case_id": case.id,
                    "rule_id": case.rule_id,
                    "gate_outcome": "skip",
                    "reasons": reason_values,
                }
            ),
            artifact_digests={},
            metadata={
                "gate_outcome": "skip",
                "prerequisite_reasons": reason_values,
                "network_request_count": 0,
            },
        )


@dataclass(frozen=True, slots=True)
class EntraObservationRequest:
    endpoint: str
    application_id: str
    fic_identifier: str
    case_id: str
    rule_id: str
    run_label: str
    request_ordinal: int
    timeout_seconds: int = 10


@dataclass(frozen=True, slots=True)
class HttpObservation:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: int


class HttpTransport(Protocol):
    def send(self, request: EntraObservationRequest) -> HttpObservation: ...


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def evaluate_entra_gate(config: EntraGateConfig) -> GateResult:
    """Return a passed gate only when every bounded prerequisite is exact."""

    reasons: list[ReasonCode] = []
    if config.tenant_id is None:
        reasons.append(ReasonCode.TENANT_CONTEXT_MISSING)
    elif (
        not _canonical_uuid(config.tenant_id)
        or not isinstance(config.allowed_tenant_ids, frozenset)
        or config.tenant_id not in config.allowed_tenant_ids
    ):
        reasons.append(ReasonCode.TENANT_CONTEXT_NOT_ALLOWED)
    if (
        not _canonical_uuid(config.application_id)
        or config.application_is_disposable is not True
    ):
        reasons.append(ReasonCode.DISPOSABLE_APPLICATION_MISSING)
    if (
        not isinstance(config.authority_host, str)
        or not isinstance(config.allowed_authority_hosts, frozenset)
        or config.authority_host != config.authority_host.lower()
        or config.authority_host not in config.allowed_authority_hosts
        or ":" in config.authority_host
        or "/" in config.authority_host
    ):
        reasons.append(ReasonCode.AUTHORITY_HOST_NOT_ALLOWED)
    if (
        not isinstance(config.fic_identifier, str)
        or not _FIC_IDENTIFIER.fullmatch(config.fic_identifier)
    ):
        reasons.append(ReasonCode.FIC_IDENTIFIER_MISSING)
    if not isinstance(config.directory_roles, frozenset) or config.directory_roles:
        reasons.append(ReasonCode.DIRECTORY_ROLE_NOT_MINIMAL)
    if config.redaction_test_passed is not True:
        reasons.append(ReasonCode.REDACTION_PROBE_FAILED)
    if (
        type(config.request_ceiling) is not int
        or not 1 <= config.request_ceiling <= _MAX_REQUESTS
    ):
        reasons.append(ReasonCode.REQUEST_CEILING_INVALID)
    if not isinstance(config.run_label, str) or not _LABEL.fullmatch(config.run_label):
        reasons.append(ReasonCode.RUN_LABEL_MISSING)

    if reasons:
        return GateResult("skip", tuple(reasons), None)

    assert config.tenant_id is not None
    assert config.application_id is not None
    assert config.authority_host is not None
    assert config.fic_identifier is not None
    assert config.run_label is not None
    endpoint = (
        f"https://{config.authority_host}/{config.tenant_id}/oauth2/v2.0/token"
    )
    gate = PassedGate(
        tenant_id=config.tenant_id,
        application_id=config.application_id,
        authority_host=config.authority_host,
        fic_identifier=config.fic_identifier,
        run_label=config.run_label,
        request_ceiling=config.request_ceiling,
        endpoint=endpoint,
        _budget=_RequestBudget(config.request_ceiling),
    )
    return GateResult("pass", (), gate)


def _observation_digest(case: TestCase, gate: PassedGate) -> str:
    return canonical_digest(
        {
            "case_id": case.id,
            "rule_id": case.rule_id,
            "seed": case.seed,
            "tenant_digest": digest_identifier("entra-tenant", gate.tenant_id),
            "application_digest": digest_identifier(
                "entra-application", gate.application_id
            ),
            "fic_digest": digest_identifier("entra-fic", gate.fic_identifier),
            "authority_host": gate.authority_host,
            "run_label": gate.run_label,
        }
    )


def _non_response_record(
    case: TestCase,
    gate: PassedGate,
    outcome: Literal["skip", "inconclusive"],
    reason: ReasonCode,
    metadata: Mapping[str, JSONValue],
) -> EvidenceRecord:
    return EvidenceRecord(
        case_id=case.id,
        rule_id=case.rule_id,
        outcome=outcome,
        reason=reason,
        evidence_class="entra-observation",
        input_digest=_observation_digest(case, gate),
        artifact_digests={},
        metadata=metadata,
    )


def _parse_response(response: HttpObservation) -> dict[str, JSONValue]:
    if type(response.status_code) is not int or not 100 <= response.status_code <= 599:
        raise ValueError("response status is outside the HTTP range")
    if (
        type(response.elapsed_ms) is not int
        or not 0 <= response.elapsed_ms <= _MAX_ELAPSED_MS
    ):
        raise ValueError("response timing is outside the configured bound")
    if not isinstance(response.body, bytes) or len(response.body) > _MAX_RESPONSE_BYTES:
        raise ValueError("response body exceeds the configured bound")
    try:
        document = parse_json_object(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("response is not one bounded JSON object") from error
    correlation_id: str | None = None
    correlation_count = 0
    for name, value in response.headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("response headers must be strings")
        if name.lower() == "x-ms-request-id":
            correlation_count += 1
            correlation_id = value
    if correlation_count > 1:
        raise ValueError("response correlation ID is ambiguous")
    if correlation_id is not None and not _canonical_uuid(correlation_id):
        raise ValueError("response correlation ID is not a canonical UUID")

    error_code: str | None = None
    if response.status_code >= 400:
        raw_error = document.get("error")
        if not isinstance(raw_error, str) or not _ERROR_CODE.fullmatch(raw_error):
            raise ValueError("error response lacks one documented error code")
        error_code = raw_error
    return {
        "status_code": response.status_code,
        "error_code": error_code,
        "correlation_id_digest": (
            digest_identifier("entra-correlation-id", correlation_id)
            if correlation_id is not None
            else None
        ),
        "elapsed_ms": response.elapsed_ms,
    }


def observe_entra_case(
    case: TestCase, gate: PassedGate, transport: HttpTransport
) -> EvidenceRecord:
    """Make at most one budgeted call and retain bounded response metadata only."""

    if not case.rule_id.startswith("WIF-"):
        raise ValueError("Entra observations require a WIF invariant case")
    ordinal = gate.consume_request()
    if ordinal is None:
        return _non_response_record(
            case,
            gate,
            "skip",
            ReasonCode.REQUEST_CEILING_REACHED,
            {
                "run_label": gate.run_label,
                "network_request_count": gate.requests_used,
            },
        )
    request = EntraObservationRequest(
        endpoint=gate.endpoint,
        application_id=gate.application_id,
        fic_identifier=gate.fic_identifier,
        case_id=case.id,
        rule_id=case.rule_id,
        run_label=gate.run_label,
        request_ordinal=ordinal,
    )
    try:
        response = transport.send(request)
    except Exception:
        return _non_response_record(
            case,
            gate,
            "inconclusive",
            ReasonCode.TRANSPORT_FAILED,
            {
                "run_label": gate.run_label,
                "authority_host": gate.authority_host,
                "request_ordinal": ordinal,
                "network_request_count": gate.requests_used,
            },
        )
    try:
        response_metadata = _parse_response(response)
    except (AttributeError, TypeError, ValueError):
        return _non_response_record(
            case,
            gate,
            "inconclusive",
            ReasonCode.RESPONSE_INVALID,
            {
                "run_label": gate.run_label,
                "authority_host": gate.authority_host,
                "request_ordinal": ordinal,
                "network_request_count": gate.requests_used,
            },
        )
    metadata: dict[str, JSONValue] = {
        "run_label": gate.run_label,
        "authority_host": gate.authority_host,
        "request_ordinal": ordinal,
        **response_metadata,
    }
    return EvidenceRecord(
        case_id=case.id,
        rule_id=case.rule_id,
        outcome="observe",
        reason=ReasonCode.OBSERVATION_RECORDED,
        evidence_class="entra-observation",
        input_digest=_observation_digest(case, gate),
        artifact_digests={},
        metadata=metadata,
    )


def closed_environment_config() -> EntraGateConfig:
    """Return the explicit no-context configuration used by isolated labs."""

    return EntraGateConfig(
        tenant_id=None,
        allowed_tenant_ids=frozenset(),
        application_id=None,
        application_is_disposable=False,
        authority_host=None,
        allowed_authority_hosts=frozenset(),
        fic_identifier=None,
        directory_roles=frozenset(),
        redaction_test_passed=False,
        request_ceiling=0,
        run_label=None,
    )


def record_closed_environment(destination: Path, environment: str) -> Path:
    """Seal one distinct no-request record for an isolated lab environment."""

    if not _LABEL.fullmatch(environment):
        raise ValueError("environment must be a bounded label")
    result = evaluate_entra_gate(closed_environment_config())
    record = result.skip_record(
        TestCase(
            id=f"wif-live-gate-{environment}",
            rule_id="WIF-BIND-001",
            kind="observe",
            source_case="current-environment-gate",
            seed=20261030,
        )
    )
    writer = EvidenceWriter(destination)
    writer.append(record)
    return writer.seal().path


def _main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the closed Entra gate.")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--environment", default="current-environment")
    arguments = parser.parse_args()
    record_closed_environment(
        arguments.destination,
        arguments.environment,
    )


if __name__ == "__main__":
    _main()
