from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools" / "build_detailed_report.py"
TEMPLATE = ROOT / "reports" / "program1-detailed-report.template.html"
VERIFICATION = ROOT / "reports" / "program1-detailed-report-verification.json"

EXPECTED_OUTCOMES = {
    "accept": 5,
    "reject": 1,
    "observe": 10,
    "skip": 6,
    "inconclusive": 3,
}
EXPECTED_VISUALS = {
    "architecture-map",
    "trust-pipeline",
    "wif-state-machine",
    "token-exchange-flow",
    "pac-bounds-model",
    "dmsa-state-graph",
    "cloud-trust-gate",
    "evidence-chain",
    "results-chart",
    "coverage-heatmap",
    "commit-timeline",
}
EXPECTED_SECTIONS = {
    "executive-summary",
    "scope-and-claims",
    "formal-method",
    "laboratory-architecture",
    "workload-identity",
    "token-exchange",
    "openid-connect",
    "ms-pac",
    "dmsa",
    "cloud-kerberos",
    "test-strategy",
    "observations",
    "evidence-integrity",
    "limitations",
    "recommendations",
    "appendix-invariants",
    "appendix-observations",
    "appendix-hashes",
    "appendix-commits",
    "appendix-reproduction",
    "appendix-glossary",
    "appendix-sources",
}


def _load_builder():
    assert BUILDER.is_file(), "detailed report builder is not implemented"
    specification = importlib.util.spec_from_file_location(
        "build_detailed_report", BUILDER
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_report_model_is_bound_to_reviewed_program1_facts() -> None:
    builder = _load_builder()
    model = builder.build_report_model(ROOT)

    assert len(model["invariants"]) == 37
    assert len(model["observations"]) == 25
    assert model["outcomes"] == EXPECTED_OUTCOMES
    assert model["test_results"] == {
        "ubuntu": 148,
        "windows": 50,
        "total": 198,
        "conditional_integrations": 3,
    }
    assert model["manifest"]["ledger_sha256"] == (
        "9852c4e00a4c1b25165708541774ba23975ec6c97acd6e0c2b90c6377633f44c"
    )
    assert model["assessment"] == {
        "cwe": "not assessed",
        "cvss": "not assessed",
        "product_deviation": "not established",
    }


def test_template_declares_every_required_section_and_visual() -> None:
    assert TEMPLATE.is_file(), "detailed report template is not implemented"
    template = TEMPLATE.read_text(encoding="utf-8")

    for section_id in EXPECTED_SECTIONS:
        assert f'id="{section_id}"' in template
    for visual_id in EXPECTED_VISUALS:
        assert f'id="{visual_id}"' in template
    assert template.count("{{INVARIANT_ROWS}}") == 1
    assert template.count("{{OBSERVATION_ROWS}}") == 1
    assert template.count("{{SOURCE_ROWS}}") == 1
    assert template.count("{{ARTIFACT_HASH_ROWS}}") == 1
    assert template.count("{{COMMIT_ROWS}}") == 1


def test_builder_renders_complete_public_safe_html(tmp_path: Path) -> None:
    builder = _load_builder()
    output = tmp_path / "report.html"
    data_output = tmp_path / "report-data.json"

    builder.build_report(ROOT, TEMPLATE, output, data_output)
    html = output.read_text(encoding="utf-8")

    assert "{{" not in html and "}}" not in html
    assert "37 formal invariyant" in html
    assert "25 normalize gözlem" in html
    assert "198 test" in html
    assert "CWE ve CVSS atanmadı" in html
    for invariant in builder.build_report_model(ROOT)["invariants"]:
        assert invariant["id"] in html
    for observation in builder.build_report_model(ROOT)["observations"]:
        assert observation["case_id"] in html
    builder.validate_public_text(html)
    builder.validate_public_text(data_output.read_text(encoding="utf-8"))


def test_public_safety_gate_rejects_credential_shaped_text() -> None:
    builder = _load_builder()

    with pytest.raises(ValueError, match="credential-shaped"):
        builder.validate_public_text("client_secret: example")


def test_verification_manifest_matches_rendered_artifacts() -> None:
    document = json.loads(VERIFICATION.read_text(encoding="utf-8"))

    assert document["format_version"] == 1
    assert document["source_binding"] == {
        "invariants": 37,
        "ledger_sha256": (
            "9852c4e00a4c1b25165708541774ba23975ec6c97acd6e0c2b90c6377633f44c"
        ),
        "observations": 25,
        "outcomes": EXPECTED_OUTCOMES,
    }
    assert document["pdf_validation"]["pages"] == 40
    assert document["visual_review"]["status"] == "pass"
    for descriptor in document["artifacts"].values():
        path = ROOT / descriptor["path"]
        assert path.stat().st_size == descriptor["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == descriptor["sha256"]
