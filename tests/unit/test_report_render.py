from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from identity_invariants.decisions import InvariantRule, ReasonCode
from identity_invariants.evidence.ledger import EvidenceRecord, EvidenceWriter
from identity_invariants.reports.render import (
    render_invariant_matrix,
    render_technical_report,
    validate_report_safety,
)


def _rule(rule_id: str, source: str) -> InvariantRule:
    return InvariantRule(
        id=rule_id,
        source=source,
        source_title=f"{source} primary specification",
        source_revision=f"{source} revision",
        source_primary_url=f"https://example.test/{source.lower()}",
        section="1.2",
        summary=f"{rule_id} retains its bounded contract.",
        evidence_class="spec-oracle",
        positive_cases=(f"{rule_id.lower()}-positive",),
        negative_cases=(f"{rule_id.lower()}-negative",),
        observe_cases=(),
    )


def _record(
    rule_id: str,
    case_id: str,
    outcome: str,
    reason: ReasonCode,
) -> EvidenceRecord:
    return EvidenceRecord(
        case_id=case_id,
        rule_id=rule_id,
        outcome=outcome,
        reason=reason,
        evidence_class="spec-oracle",
        input_digest="a" * 64,
        artifact_digests={"source-ledger": "b" * 64},
        metadata={"profile": "bounded-report-test"},
    )


def _seal(
    tmp_path: Path,
    records: list[EvidenceRecord],
    *,
    source_hash: str = "c" * 64,
) -> Path:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    for record in records:
        writer.append(record)
    manifest = writer.seal()
    document = json.loads(manifest.path.read_text(encoding="utf-8"))
    document["environment_fingerprint"] = {
        "network": "isolated private switch; no default route",
        "ubuntu": "Ubuntu 24.04 / Python 3.12",
        "windows": "Windows Server 2025 build 26100",
    }
    document["source_manifests"] = {"windows-lab": source_hash}
    manifest.path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest.path


def test_matrix_is_stable_source_mapped_and_explicit_about_outcomes() -> None:
    rules = (_rule("Z-RULE-001", "SOURCE-Z"), _rule("A-RULE-001", "SOURCE-A"))
    records = [
        _record(
            "Z-RULE-001",
            "z-inconclusive",
            "inconclusive",
            ReasonCode.RESPONSE_INVALID,
        ),
        _record(
            "A-RULE-001",
            "a-skipped",
            "skip",
            ReasonCode.TENANT_CONTEXT_MISSING,
        ),
    ]

    matrix = render_invariant_matrix(rules, list(reversed(records)))

    assert matrix.index("A-RULE-001") < matrix.index("Z-RULE-001")
    assert "[SOURCE-A primary specification](https://example.test/source-a)" in matrix
    assert "[SOURCE-Z primary specification](https://example.test/source-z)" in matrix
    assert "`skip`" in matrix
    assert "`inconclusive`" in matrix
    assert "tenant_context_missing" in matrix
    assert "response_invalid" in matrix


def test_matrix_separates_catalog_and_observed_evidence_classes() -> None:
    rule = replace(_rule("A-RULE-001", "SOURCE-A"), evidence_class="local-adapter")
    record = {
        "artifact_digests": {},
        "case_id": "windows-observation",
        "evidence_class": "windows-observation",
        "outcome": "observe",
        "reason": "observation_recorded",
        "rule_id": rule.id,
    }

    matrix = render_invariant_matrix((rule,), [record])

    assert "Catalog class" in matrix
    assert "Observed class" in matrix
    assert "`local-adapter`" in matrix
    assert "`windows-observation`" in matrix


def test_report_is_reproducible_and_contains_required_boundaries(
    tmp_path: Path,
) -> None:
    rules = (_rule("A-RULE-001", "SOURCE-A"), _rule("Z-RULE-001", "SOURCE-Z"))
    manifest = _seal(
        tmp_path,
        [
            _record("A-RULE-001", "accepted", "accept", ReasonCode.ACCEPTED),
            _record(
                "Z-RULE-001",
                "not-observed",
                "inconclusive",
                ReasonCode.RESPONSE_INVALID,
            ),
        ],
    )

    first = render_technical_report(manifest, rules, tmp_path / "first.md")
    second = render_technical_report(manifest, rules, tmp_path / "second.md")

    assert first.read_bytes() == second.read_bytes()
    assert first.with_suffix(".json").read_bytes() == second.with_suffix(
        ".json"
    ).read_bytes()
    report = first.read_text(encoding="utf-8")
    assert "CWE: `not assessed`" in report
    assert "CVSS: `not assessed`" in report
    assert "isolated private switch; no default route" in report
    assert "windows-lab" in report
    assert "c" * 64 in report
    assert "## Limitations" in report
    assert "direct service logon" in report
    validate_report_safety(first)
    validate_report_safety(first.with_suffix(".json"))


def test_report_rejects_modified_evidence(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    ledger = tmp_path / "evidence.jsonl"
    ledger.write_text(ledger.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        render_technical_report(manifest, (rule,), tmp_path / "report.md")


def test_matrix_rejects_unknown_rule_records() -> None:
    record = _record("UNKNOWN-001", "unknown", "accept", ReasonCode.ACCEPTED)

    with pytest.raises(ValueError, match="unknown invariant"):
        render_invariant_matrix((_rule("A-RULE-001", "SOURCE-A"),), [record])


def test_matrix_rejects_unsafe_identifiers_and_non_https_sources() -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    unsafe_record = {
        "artifact_digests": {},
        "case_id": "case`](https://untrusted.example)",
        "evidence_class": "spec-oracle",
        "outcome": "accept",
        "reason": "accepted",
        "rule_id": rule.id,
    }

    with pytest.raises(ValueError, match="case_id"):
        render_invariant_matrix((rule,), [unsafe_record])
    with pytest.raises(ValueError, match="HTTPS"):
        render_invariant_matrix(
            (replace(rule, source_primary_url="http://example.test/source"),),
            [],
        )


@pytest.mark.parametrize(
    "unsafe_content",
    [
        "-----BEGIN PRIVATE KEY-----",
        "Authorization: Bearer reusable-value",
        '"client_secret":"reusable-value"',
        "aaaaaaaa.bbbbbbbb.cccccccc",
        r"C:\Hyper-V\BluexLab\secrets\windows-admin.credential.xml",
        "tenant_id: 11111111-1111-4111-8111-111111111111",
    ],
)
def test_report_safety_rejects_secret_and_identifier_shapes(
    tmp_path: Path, unsafe_content: str
) -> None:
    path = tmp_path / "unsafe.md"
    path.write_text(unsafe_content, encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe report content"):
        validate_report_safety(path)


def test_report_output_does_not_depend_on_manifest_key_order(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    original = json.loads(manifest.read_text(encoding="utf-8"))
    reversed_document = dict(reversed(list(original.items())))
    manifest.write_text(
        json.dumps(reversed_document, indent=4) + "\n", encoding="utf-8"
    )

    output = render_technical_report(manifest, (rule,), tmp_path / "report.md")

    assert output.exists()
    validate_report_safety(output)


def test_report_rejects_boolean_manifest_version(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["format_version"] = True
    manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="format version"):
        render_technical_report(manifest, (rule,), tmp_path / "report.md")


def test_report_escapes_html_in_manifest_text(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["environment_fingerprint"]["note"] = "<script>alert(1)</script>"
    manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    output = render_technical_report(manifest, (rule,), tmp_path / "report.md")
    report = output.read_text(encoding="utf-8")

    assert "<script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report


def test_unsafe_render_does_not_replace_existing_report(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["environment_fingerprint"]["tenant"] = (
        "11111111-1111-4111-8111-111111111111"
    )
    manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.md"
    output.write_text("existing report\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe report content"):
        render_technical_report(manifest, (rule,), output)

    assert output.read_text(encoding="utf-8") == "existing report\n"


def test_render_rejects_secret_shape_in_unrendered_metadata(tmp_path: Path) -> None:
    rule = _rule("A-RULE-001", "SOURCE-A")
    manifest = _seal(
        tmp_path,
        [_record(rule.id, "accepted", "accept", ReasonCode.ACCEPTED)],
    )
    ledger = tmp_path / "evidence.jsonl"
    document = json.loads(ledger.read_text(encoding="utf-8"))
    document["metadata"] = {"note": "Authorization: Bearer reusable-value"}
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    ledger.write_text(encoded, encoding="utf-8")
    manifest_document = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_document["ledger_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
    manifest.write_text(
        json.dumps(manifest_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsafe report content"):
        render_technical_report(manifest, (rule,), tmp_path / "report.md")
