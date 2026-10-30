"""Assemble source-preserving public identity evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from identity_invariants.canonical import JSONValue, parse_json_object
from identity_invariants.decisions import (
    DecisionClass,
    EvidenceClass,
    ReasonCode,
)
from identity_invariants.evidence.ledger import (
    EvidenceManifest,
    EvidenceRecord,
    EvidenceWriter,
    verify_manifest,
)
from identity_invariants.vectors.generator import canonical_digest


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_NAMES = (
    "task7-windows-ledger",
    "task8-pac-ledger",
    "task9-cloud-gate",
    "task9-ubuntu-ledger",
    "task9-windows-ledger",
)
_OUTCOMES = {"accept", "reject", "observe", "skip", "inconclusive"}
_SIGNATURE_ROLES = ("server", "kdc", "ticket", "extended_kdc")
_PAC_BUFFER_TYPES = [1, 6, 7, 10, 12, 16, 19]


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _line_digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return dict(value)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _reason(value: object) -> ReasonCode:
    try:
        return ReasonCode(_string(value, "reason"))
    except ValueError as error:
        raise ValueError("source record reason code is not declared") from error


def _outcome(value: object) -> DecisionClass:
    outcome = _string(value, "outcome")
    if outcome not in _OUTCOMES:
        raise ValueError("source record outcome is not declared")
    return cast(DecisionClass, outcome)


def _json_lines(path: Path) -> list[tuple[dict[str, JSONValue], str]]:
    records: list[tuple[dict[str, JSONValue], str]] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line:
            raise ValueError("source ledger contains an empty line")
        records.append((parse_json_object(line), _line_digest(line)))
    if not records:
        raise ValueError("source ledger is empty")
    return records


def _input_digest(
    source: str, source_records: Mapping[str, str], rule_id: str, case_id: str
) -> str:
    return canonical_digest(
        {
            "case_id": case_id,
            "rule_id": rule_id,
            "source": source,
            "source_records": dict(sorted(source_records.items())),
        }
    )


def _record(
    *,
    source: str,
    source_digest: str,
    source_records: Mapping[str, str],
    case_id: str,
    rule_id: str,
    outcome: DecisionClass,
    reason: ReasonCode,
    evidence_class: EvidenceClass,
) -> EvidenceRecord:
    artifacts = {"source-ledger": source_digest, **source_records}
    return EvidenceRecord(
        case_id=case_id,
        rule_id=rule_id,
        outcome=outcome,
        reason=reason,
        evidence_class=evidence_class,
        input_digest=_input_digest(source, source_records, rule_id, case_id),
        artifact_digests=artifacts,
        metadata={"source": source},
    )


def _task7_records(path: Path, source_digest: str) -> list[EvidenceRecord]:
    public: list[EvidenceRecord] = []
    for document, record_digest in _json_lines(path):
        schema_version = document.get("schema_version")
        if type(schema_version) is not int or schema_version != 1:
            raise ValueError("Task 7 source schema version is not supported")
        if document.get("adapter") != "windows-dmsa":
            raise ValueError("Task 7 source adapter is not windows-dmsa")
        if document.get("evidence_class") != "windows-observation":
            raise ValueError("Task 7 source evidence class is invalid")
        case_id = _string(document.get("case_id"), "case_id")
        values = document.get("invariant_ids")
        if not isinstance(values, list) or not values:
            raise ValueError("Task 7 source requires invariant IDs")
        rule_ids = tuple(_string(value, "invariant_id") for value in values)
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("Task 7 source contains duplicate invariant IDs")
        outcome = _outcome(document.get("outcome"))
        reason = _reason(document.get("reason"))
        for rule_id in rule_ids:
            projected_case = case_id
            if len(rule_ids) > 1:
                projected_case = f"{case_id}--{rule_id.lower()}"
            public.append(
                _record(
                    source="task7-windows-ledger",
                    source_digest=source_digest,
                    source_records={"source-record": record_digest},
                    case_id=projected_case,
                    rule_id=rule_id,
                    outcome=outcome,
                    reason=reason,
                    evidence_class="windows-observation",
                )
            )
    return public


def _pac_sources(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    by_role: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for document, record_digest in _json_lines(path):
        kdc = _mapping(document.get("kdc"), "PAC KDC")
        role = _string(kdc.get("role"), "PAC KDC role")
        if role not in {"rwdc", "rodc"} or role in by_role:
            raise ValueError("PAC source requires one RWDC and one RODC record")
        by_role[role] = cast(dict[str, Any], document)
        digests[f"source-record-{role}"] = record_digest
    if set(by_role) != {"rwdc", "rodc"}:
        raise ValueError("PAC source requires one RWDC and one RODC record")
    return by_role, digests


def _validate_pac_sources(records: Mapping[str, Mapping[str, Any]]) -> None:
    for role in ("rwdc", "rodc"):
        document = records[role]
        kdc = _mapping(document.get("kdc"), f"{role} KDC")
        pac = _mapping(document.get("pac"), f"{role} PAC")
        ticket = _mapping(document.get("ticket"), f"{role} ticket")
        if document.get("cache_isolated") is not True:
            raise ValueError(f"{role} PAC cache is not isolated")
        if kdc.get("matched_request") is not True:
            raise ValueError(f"{role} KDC did not match its request")
        if pac.get("buffer_types") != _PAC_BUFFER_TYPES:
            raise ValueError(f"{role} PAC buffer set is not the observed profile")
        if pac.get("attributes_present") is not False:
            raise ValueError(f"{role} PAC attributes state is not absent")
        if pac.get("requestor_present") is not False:
            raise ValueError(f"{role} PAC requestor state is not absent")
        if ticket.get("rodc_identifier") is not None:
            raise ValueError(f"{role} service ticket carries an RODC identifier")
        signatures = pac.get("signatures")
        if not isinstance(signatures, list):
            raise ValueError(f"{role} PAC signatures must be an array")
        signature_roles = [
            _string(_mapping(item, "PAC signature").get("role"), "signature role")
            for item in signatures
        ]
        if tuple(signature_roles) != _SIGNATURE_ROLES:
            raise ValueError(f"{role} PAC signature roles are not ordered")
        identifier = kdc.get("rodc_identifier")
        if role == "rwdc":
            if identifier is not None:
                raise ValueError("RWDC KDC carries an RODC identifier")
        elif type(identifier) is not int or not 0 < identifier <= 0xFFFF:
            raise ValueError("RODC KDC identifier is invalid")
        for item in signatures:
            signature = _mapping(item, "PAC signature")
            expected = None
            if role == "rodc" and signature.get("role") != "server":
                expected = identifier
            if signature.get("rodc_identifier") != expected:
                raise ValueError(f"{role} PAC signature identifier is invalid")


def _task8_records(path: Path, source_digest: str) -> list[EvidenceRecord]:
    sources, record_digests = _pac_sources(path)
    _validate_pac_sources(sources)
    observations = (
        (
            "pac-attributes-service-ticket",
            "PAC-ATTR-001",
            "observe",
            ReasonCode.ATTRIBUTES_BUFFER_ABSENT,
        ),
        (
            "pac-domain-local-processing",
            "PAC-DLG-001",
            "observe",
            ReasonCode.SERVICE_TICKET_BUFFERS_OBSERVED,
        ),
        (
            "pac-requestor-tgt-boundary",
            "PAC-REQ-001",
            "inconclusive",
            ReasonCode.TGT_REQUESTOR_NOT_ASSESSED,
        ),
        (
            "pac-rodc-identifier",
            "PAC-RODC-001",
            "observe",
            ReasonCode.RODC_IDENTIFIER_OBSERVED,
        ),
        (
            "pac-signature-roles",
            "PAC-SIG-001",
            "observe",
            ReasonCode.SIGNATURE_ROLES_OBSERVED,
        ),
        (
            "pac-service-ticket-issuance",
            "PAC-TGS-001",
            "observe",
            ReasonCode.SERVICE_TICKET_ISSUANCE_OBSERVED,
        ),
    )
    return [
        _record(
            source="task8-pac-ledger",
            source_digest=source_digest,
            source_records=record_digests,
            case_id=case_id,
            rule_id=rule_id,
            outcome=cast(DecisionClass, outcome),
            reason=reason,
            evidence_class="windows-observation",
        )
        for case_id, rule_id, outcome, reason in observations
    ]


def _task9_cloud_record(
    path: Path, source_digest: str
) -> list[EvidenceRecord]:
    document = parse_json_object(path.read_text(encoding="utf-8-sig"))
    format_version = document.get("format_version")
    if (
        type(format_version) is not int
        or format_version != 1
        or document.get("outcome") != "skip"
    ):
        raise ValueError("Cloud gate source is not one supported skip result")
    request_count = document.get("network_request_count")
    if type(request_count) is not int or request_count != 0:
        raise ValueError("Cloud gate source made an external request")
    inventory = _mapping(document.get("inventory"), "Cloud gate inventory")
    required_flags = {
        "AzureAdKerberosObject",
        "CertificateTrustPolicySelected",
        "ClientJoined",
        "CloudTrustPolicySelected",
        "LineOfSight",
        "PartialTgt",
        "PasswordReplicationPolicyIntact",
        "Server2025Rwdc",
        "Windows11Client",
    }
    if set(inventory) != required_flags or any(
        not isinstance(inventory[name], bool) for name in required_flags
    ):
        raise ValueError("Cloud gate inventory is not a bounded boolean map")
    reasons = document.get("reason_codes")
    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) for reason in reasons
    ):
        raise ValueError("Cloud gate source reason codes are invalid")
    expected_reasons: list[str] = []
    if not inventory["Server2025Rwdc"]:
        expected_reasons.append("server_2025_rwdc_missing")
    if not inventory["AzureAdKerberosObject"]:
        expected_reasons.append("cloud_kerberos_object_missing")
    if not inventory["PasswordReplicationPolicyIntact"]:
        expected_reasons.append("password_replication_policy_unverified")
    if not inventory["CloudTrustPolicySelected"]:
        expected_reasons.append("cloud_trust_policy_unverified")
    if inventory["CertificateTrustPolicySelected"]:
        expected_reasons.append("certificate_trust_precedence")
    if not inventory["Windows11Client"] or not inventory["ClientJoined"]:
        expected_reasons.append("windows_11_client_missing")
    if not inventory["LineOfSight"]:
        expected_reasons.append("line_of_sight_missing")
    if not inventory["PartialTgt"]:
        expected_reasons.append("partial_tgt_missing")
    if reasons != expected_reasons:
        raise ValueError("Cloud gate reason codes do not match inventory")
    required_reasons = {
        "cloud_kerberos_object_missing",
        "password_replication_policy_unverified",
        "cloud_trust_policy_unverified",
        "windows_11_client_missing",
        "line_of_sight_missing",
        "partial_tgt_missing",
    }
    if not required_reasons.issubset(reasons):
        raise ValueError("Cloud gate source lacks prerequisite reasons")
    source_records = {"source-record": source_digest}
    observations = (
        (
            "ckt-line-of-sight",
            "CKT-LOS-001",
            ReasonCode.LINE_OF_SIGHT_MISSING,
        ),
        (
            "ckt-partial-tgt-gate",
            "CKT-PARTIAL-001",
            ReasonCode.PARTIAL_TGT_MISSING,
        ),
        (
            "ckt-policy-precedence-gate",
            "CKT-PRECEDENCE-001",
            ReasonCode.CLOUD_TRUST_POLICY_UNVERIFIED,
        ),
        (
            "ckt-rodc-object-gate",
            "CKT-RODC-001",
            ReasonCode.CLOUD_KERBEROS_OBJECT_MISSING,
        ),
    )
    return [
        _record(
            source="task9-cloud-gate",
            source_digest=source_digest,
            source_records=source_records,
            case_id=case_id,
            rule_id=rule_id,
            outcome="skip",
            reason=reason,
            evidence_class="windows-observation",
        )
        for case_id, rule_id, reason in observations
    ]


def _task9_entra_records(
    source: str, path: Path, source_digest: str
) -> list[EvidenceRecord]:
    lines = _json_lines(path)
    if len(lines) != 1:
        raise ValueError(f"{source} must contain one closed-gate record")
    document, record_digest = lines[0]
    if document.get("evidence_class") != "entra-observation":
        raise ValueError(f"{source} evidence class is invalid")
    if document.get("rule_id") != "WIF-BIND-001":
        raise ValueError(f"{source} rule is invalid")
    input_digest = _string(document.get("input_digest"), "input_digest")
    if not _DIGEST.fullmatch(input_digest):
        raise ValueError(f"{source} input digest is invalid")
    return [
        EvidenceRecord(
            case_id=_string(document.get("case_id"), "case_id"),
            rule_id="WIF-BIND-001",
            outcome=_outcome(document.get("outcome")),
            reason=_reason(document.get("reason")),
            evidence_class="entra-observation",
            input_digest=input_digest,
            artifact_digests={
                "source-ledger": source_digest,
                "source-record": record_digest,
            },
            metadata={"source": source},
        )
    ]


def _load_config(
    path: Path,
) -> tuple[dict[str, str], dict[str, str]]:
    document = parse_json_object(path.read_text(encoding="utf-8"))
    format_version = document.get("format_version")
    if type(format_version) is not int or format_version != 1:
        raise ValueError("assembly config format version is not supported")
    environment_value = document.get("environment_fingerprint")
    environment_document = _mapping(environment_value, "environment fingerprint")
    environment = {
        _string(key, "environment key"): _string(value, "environment value")
        for key, value in environment_document.items()
    }
    source_document = _mapping(document.get("sources"), "assembly sources")
    if set(source_document) != set(_SOURCE_NAMES):
        raise ValueError("assembly config source set is incomplete")
    expected: dict[str, str] = {}
    for name in _SOURCE_NAMES:
        descriptor = _mapping(source_document[name], f"source {name}")
        if descriptor.get("kind") != name:
            raise ValueError(f"source kind mismatch: {name}")
        digest = _string(descriptor.get("sha256"), f"source digest {name}")
        if not _DIGEST.fullmatch(digest):
            raise ValueError(f"source digest is invalid: {name}")
        expected[name] = digest
    return expected, environment


def assemble_public_evidence(
    config: Path,
    sources: Mapping[str, Path],
    destination: Path,
) -> EvidenceManifest:
    """Verify exact normalized sources and emit one deterministic public index."""

    expected, environment = _load_config(config)
    if set(sources) != set(_SOURCE_NAMES):
        raise ValueError("source path set is incomplete")
    resolved = {name: Path(sources[name]).resolve() for name in _SOURCE_NAMES}
    for name, path in resolved.items():
        if _file_digest(path) != expected[name]:
            raise ValueError(f"source digest mismatch: {name}")

    records: list[EvidenceRecord] = []
    records.extend(
        _task7_records(
            resolved["task7-windows-ledger"],
            expected["task7-windows-ledger"],
        )
    )
    records.extend(
        _task8_records(
            resolved["task8-pac-ledger"],
            expected["task8-pac-ledger"],
        )
    )
    records.extend(
        _task9_cloud_record(
            resolved["task9-cloud-gate"],
            expected["task9-cloud-gate"],
        )
    )
    for name in ("task9-ubuntu-ledger", "task9-windows-ledger"):
        records.extend(_task9_entra_records(name, resolved[name], expected[name]))
    ordered = sorted(
        records,
        key=lambda record: (
            record.rule_id,
            record.case_id,
            record.outcome,
            str(record.reason),
        ),
    )
    identities = {(record.rule_id, record.case_id) for record in ordered}
    if len(identities) != len(ordered):
        raise ValueError("assembled evidence contains duplicate rule/case identities")

    destination.mkdir(parents=True, exist_ok=True)
    writer = EvidenceWriter(destination / "evidence.jsonl")
    for record in ordered:
        writer.append(record)
    manifest = writer.seal(destination / "manifest.json")
    manifest_document = json.loads(manifest.path.read_text(encoding="utf-8"))
    manifest_document["environment_fingerprint"] = environment
    manifest_document["source_manifests"] = dict(sorted(expected.items()))
    temporary = manifest.path.with_suffix(manifest.path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(manifest.path)
    verify_manifest(manifest.path)
    return manifest


def _source_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or name not in _SOURCE_NAMES or not raw_path:
        raise argparse.ArgumentTypeError("source must be NAME=PATH")
    return name, Path(raw_path)


def _main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Assemble verified public identity evidence."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--source", type=_source_argument, action="append", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    source_pairs = cast(list[tuple[str, Path]], arguments.source)
    sources = dict(source_pairs)
    if len(sources) != len(source_pairs):
        parser.error("each source name must occur once")
    manifest = assemble_public_evidence(arguments.config, sources, arguments.output)
    print(
        f"assembled {manifest.record_count} records: "
        f"{manifest.ledger_sha256}"
    )


if __name__ == "__main__":
    _main()
