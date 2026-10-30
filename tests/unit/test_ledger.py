from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import (
    EvidenceRecord,
    EvidenceWriter,
    verify_manifest,
)


def _record(case_id: str = "case-1") -> EvidenceRecord:
    return EvidenceRecord(
        case_id=case_id,
        rule_id="WIF-TYPE-001",
        outcome="accept",
        reason=ReasonCode.ACCEPTED,
        evidence_class="spec-oracle",
        input_digest="a" * 64,
        artifact_digests={"decision": "b" * 64},
        metadata={"profile": "rfc7523", "attempt": 1},
    )


def test_writer_seals_and_verifies_jsonl_manifest(tmp_path: Path) -> None:
    ledger_path = tmp_path / "evidence.jsonl"
    writer = EvidenceWriter(ledger_path)
    writer.append(_record("case-1"))
    writer.append(_record("case-2"))

    manifest = writer.seal()

    assert manifest.record_count == 2
    assert len(manifest.ledger_sha256) == 64
    verify_manifest(manifest.path)
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["case_id"] for line in lines] == ["case-1", "case-2"]


def test_manifest_detects_ledger_modification(tmp_path: Path) -> None:
    ledger_path = tmp_path / "evidence.jsonl"
    writer = EvidenceWriter(ledger_path)
    writer.append(_record())
    manifest = writer.seal()
    ledger_path.write_text(
        ledger_path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        verify_manifest(manifest.path)


def test_writer_rejects_append_after_seal(tmp_path: Path) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    writer.append(_record())
    writer.seal()

    with pytest.raises(RuntimeError, match="sealed"):
        writer.append(_record("late"))


def test_writer_rejects_undeclared_reason_code(tmp_path: Path) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    record = replace(
        _record(),
        reason=cast(ReasonCode, "unregistered_observation_reason"),
    )

    with pytest.raises(ValueError, match="reason code"):
        writer.append(record)


@pytest.mark.parametrize(
    "embedded_value",
    [
        "request Authorization: Bearer reusable-token-material",
        "prefix eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlIn0.signature suffix",
        "config client_secret=must-not-be-retained",
        "prefix -----BEGIN PRIVATE KEY----- suffix",
        r"C:\Hyper-V\BluexLab\secrets\windows-admin.credential.xml",
    ],
)
def test_writer_rejects_embedded_secret_shapes(
    tmp_path: Path, embedded_value: str
) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    record = replace(
        _record(),
        metadata={"nested": {"diagnostic": f"safe context {embedded_value}"}},
    )

    with pytest.raises(ValueError, match="prohibited value shape"):
        writer.append(record)
