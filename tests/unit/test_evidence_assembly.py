from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from identity_invariants.reports.assemble import assemble_public_evidence


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


def _task7_records() -> list[dict[str, object]]:
    return [
        {
            "schema_version": 1,
            "case_id": "dmsa-started-to-complete",
            "invariant_ids": [
                "DMSA-STATE-001",
                "DMSA-ACL-001",
                "DMSA-SPN-001",
            ],
            "adapter": "windows-dmsa",
            "evidence_class": "windows-observation",
            "outcome": "accept",
            "reason": "ordered_completion",
        },
        {
            "schema_version": 1,
            "case_id": "dmsa-reset-to-documented-state",
            "invariant_ids": ["DMSA-ROLLBACK-001"],
            "adapter": "windows-dmsa",
            "evidence_class": "windows-observation",
            "outcome": "observe",
            "reason": "state_links_restored_enrollment_cleared",
        },
        {
            "schema_version": 1,
            "case_id": "dmsa-undo-to-documented-state",
            "invariant_ids": ["DMSA-ROLLBACK-001"],
            "adapter": "windows-dmsa",
            "evidence_class": "windows-observation",
            "outcome": "observe",
            "reason": "state_links_restored_enrollment_cleared",
        },
        {
            "schema_version": 1,
            "case_id": "dmsa-standalone",
            "invariant_ids": ["DMSA-STATE-001"],
            "adapter": "windows-dmsa",
            "evidence_class": "windows-observation",
            "outcome": "inconclusive",
            "reason": "documented_state_three_not_observed",
        },
        {
            "schema_version": 1,
            "case_id": "dmsa-baseline-restore",
            "invariant_ids": ["DMSA-ROLLBACK-001"],
            "adapter": "windows-dmsa",
            "evidence_class": "windows-observation",
            "outcome": "accept",
            "reason": "checkpoint_restore_digest_match",
        },
    ]


def _pac_record(role: str) -> dict[str, object]:
    identifier = 4543 if role == "rodc" else None
    return {
        "cache_isolated": True,
        "kdc": {
            "matched_request": True,
            "role": role,
            "rodc_identifier": identifier,
        },
        "pac": {
            "attributes_present": False,
            "buffer_types": [1, 6, 7, 10, 12, 16, 19],
            "requestor_present": False,
            "signatures": [
                {
                    "role": signature_role,
                    "rodc_identifier": (
                        identifier if signature_role != "server" else None
                    ),
                }
                for signature_role in (
                    "server",
                    "kdc",
                    "ticket",
                    "extended_kdc",
                )
            ],
        },
        "ticket": {"key_version": 16, "rodc_identifier": None},
    }


def _entra_record(case_id: str) -> dict[str, object]:
    return {
        "artifact_digests": {},
        "case_id": case_id,
        "evidence_class": "entra-observation",
        "input_digest": "a" * 64,
        "metadata": {"network_request_count": 0},
        "outcome": "skip",
        "reason": "tenant_context_missing",
        "rule_id": "WIF-BIND-001",
    }


def _source_fixture(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    sources = {
        "task7-windows-ledger": tmp_path / "task7.jsonl",
        "task8-pac-ledger": tmp_path / "task8.jsonl",
        "task9-cloud-gate": tmp_path / "cloud.json",
        "task9-ubuntu-ledger": tmp_path / "ubuntu.jsonl",
        "task9-windows-ledger": tmp_path / "windows.jsonl",
    }
    _write_jsonl(sources["task7-windows-ledger"], _task7_records())
    _write_jsonl(
        sources["task8-pac-ledger"],
        [_pac_record("rodc"), _pac_record("rwdc")],
    )
    sources["task9-cloud-gate"].write_text(
        json.dumps(
            {
                "format_version": 1,
                "outcome": "skip",
                "reason_codes": [
                    "cloud_kerberos_object_missing",
                    "password_replication_policy_unverified",
                    "cloud_trust_policy_unverified",
                    "windows_11_client_missing",
                    "partial_tgt_missing",
                ],
                "network_request_count": 0,
                "inventory": {
                    "Server2025Rwdc": True,
                    "AzureAdKerberosObject": False,
                    "PasswordReplicationPolicyIntact": False,
                    "CloudTrustPolicySelected": False,
                    "CertificateTrustPolicySelected": False,
                    "Windows11Client": False,
                    "ClientJoined": False,
                    "LineOfSight": False,
                    "PartialTgt": False,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    _write_jsonl(
        sources["task9-ubuntu-ledger"],
        [_entra_record("wif-live-gate-ubuntu-lab")],
    )
    _write_jsonl(
        sources["task9-windows-ledger"],
        [_entra_record("wif-live-gate-windows-lab")],
    )
    config = tmp_path / "sources.json"
    config.write_text(
        json.dumps(
            {
                "format_version": 1,
                "environment_fingerprint": {"lab": "isolated fixture"},
                "sources": {
                    name: {"kind": name, "sha256": _digest(path)}
                    for name, path in sources.items()
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return config, sources


def test_assembler_preserves_source_outcomes_and_record_provenance(
    tmp_path: Path,
) -> None:
    config, sources = _source_fixture(tmp_path)

    manifest = assemble_public_evidence(
        config,
        sources,
        tmp_path / "first",
    )
    records = [
        json.loads(line)
        for line in (manifest.path.parent / manifest.ledger)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    by_case = {record["case_id"]: record for record in records}

    assert by_case["dmsa-standalone"]["outcome"] == "inconclusive"
    assert by_case["dmsa-standalone"]["reason"] == (
        "documented_state_three_not_observed"
    )
    for case_id in (
        "dmsa-reset-to-documented-state",
        "dmsa-undo-to-documented-state",
    ):
        assert by_case[case_id]["reason"] == (
            "state_links_restored_enrollment_cleared"
        )
    projected = {
        record["rule_id"]
        for record in records
        if record["case_id"].startswith("dmsa-started-to-complete--")
    }
    assert projected == {
        "DMSA-STATE-001",
        "DMSA-ACL-001",
        "DMSA-SPN-001",
    }
    assert all(
        "source-ledger" in record["artifact_digests"]
        for record in records
    )
    assert all(
        any(name.startswith("source-record") for name in record["artifact_digests"])
        for record in records
    )

    second = assemble_public_evidence(
        config,
        sources,
        tmp_path / "second",
    )
    assert (manifest.path.parent / manifest.ledger).read_bytes() == (
        second.path.parent / second.ledger
    ).read_bytes()


def test_assembler_rejects_source_digest_mismatch(tmp_path: Path) -> None:
    config, sources = _source_fixture(tmp_path)
    sources["task7-windows-ledger"].write_text(
        sources["task7-windows-ledger"].read_text(encoding="utf-8") + "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="source digest mismatch"):
        assemble_public_evidence(config, sources, tmp_path / "output")


def test_assembler_rejects_boolean_format_version(tmp_path: Path) -> None:
    config, sources = _source_fixture(tmp_path)
    document = json.loads(config.read_text(encoding="utf-8"))
    document["format_version"] = True
    config.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="format version"):
        assemble_public_evidence(config, sources, tmp_path / "output")
