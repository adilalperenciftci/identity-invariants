from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from identity_invariants.catalog import load_catalog
from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import EvidenceRecord, EvidenceWriter
from identity_invariants.reports.render import (
    render_technical_report,
    validate_report_safety,
)
from identity_invariants.reports.assemble import assemble_public_evidence
from identity_invariants.vectors.generator import canonical_digest


ROOT = Path(__file__).resolve().parents[2]


def _outcome(rule_id: str) -> tuple[str, ReasonCode]:
    if rule_id.startswith(("WIF-", "CKT-")):
        return "skip", ReasonCode.TENANT_CONTEXT_MISSING
    if rule_id.startswith(("PAC-", "DMSA-")):
        return "inconclusive", ReasonCode.RESPONSE_INVALID
    return "accept", ReasonCode.ACCEPTED


def test_full_catalog_report_and_verify_only_cli(tmp_path: Path) -> None:
    catalog = load_catalog(ROOT / "spec" / "invariants.yaml")
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    for rule in reversed(catalog):
        outcome, reason = _outcome(rule.id)
        writer.append(
            EvidenceRecord(
                case_id=f"report-{rule.id.lower()}",
                rule_id=rule.id,
                outcome=outcome,
                reason=reason,
                evidence_class=rule.evidence_class,
                input_digest=canonical_digest(
                    {"case_id": rule.id, "profile": "report-integration"}
                ),
                artifact_digests={"source-ledger": "d" * 64},
                metadata={"profile": "report-integration"},
            )
        )
    manifest = writer.seal()
    document = json.loads(manifest.path.read_text(encoding="utf-8"))
    document["environment_fingerprint"] = {
        "lab": "isolated report integration fixture"
    }
    document["source_manifests"] = {"fixture": "e" * 64}
    manifest.path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = render_technical_report(
        manifest.path,
        catalog,
        tmp_path / "identity-invariants.md",
    )
    validate_report_safety(report)
    validate_report_safety(report.with_suffix(".json"))

    markdown = report.read_text(encoding="utf-8")
    for rule in catalog:
        assert rule.id in markdown
        assert rule.source_primary_url in markdown
    assert "`skip`" in markdown
    assert "`inconclusive`" in markdown
    sidecar = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert sidecar["invariant_count"] == len(catalog)
    assert sidecar["record_count"] == len(catalog)
    assert sidecar["assessment"] == {
        "cwe": "not assessed",
        "cvss": "not assessed",
    }

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "identity_invariants.reports.render",
            "--verify-only",
            str(manifest.path),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "verified" in completed.stdout.lower()


def test_committed_report_matches_verified_evidence(tmp_path: Path) -> None:
    catalog = load_catalog(ROOT / "spec" / "invariants.yaml")
    generated = render_technical_report(
        ROOT / "evidence" / "manifest.json",
        catalog,
        tmp_path / "identity-invariants.md",
    )
    committed = ROOT / "reports" / "identity-invariants.md"

    validate_report_safety(committed)
    validate_report_safety(committed.with_suffix(".json"))
    assert generated.read_bytes() == committed.read_bytes()
    assert generated.with_suffix(".json").read_bytes() == committed.with_suffix(
        ".json"
    ).read_bytes()


def test_committed_evidence_matches_verified_sources(tmp_path: Path) -> None:
    configured = os.environ.get("IDENTITY_SOURCE_ROOT")
    if configured is None:
        pytest.skip("IDENTITY_SOURCE_ROOT is set only in the isolated lab")
    source_root = Path(configured)
    sources = {
        "task7-windows-ledger": source_root / "task7.jsonl",
        "task8-pac-ledger": source_root / "task8.jsonl",
        "task9-cloud-gate": source_root / "cloud.json",
        "task9-ubuntu-ledger": source_root / "ubuntu.jsonl",
        "task9-windows-ledger": source_root / "windows.jsonl",
    }

    generated = assemble_public_evidence(
        ROOT / "evidence" / "sources.json",
        sources,
        tmp_path / "assembled",
    )

    assert (generated.path.parent / generated.ledger).read_bytes() == (
        ROOT / "evidence" / "evidence.jsonl"
    ).read_bytes()
    assert generated.path.read_bytes() == (
        ROOT / "evidence" / "manifest.json"
    ).read_bytes()
