from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from identity_invariants.catalog import load_catalog, validate_catalog_coverage


ROOT = Path(__file__).resolve().parents[2]
DESIGN_RULE_IDS = {
    "WIF-TRANSPORT-001",
    "WIF-TYPE-001",
    "WIF-MATCH-001",
    "WIF-BIND-001",
    "WIF-TIME-001",
    "WIF-REPLAY-001",
    "WIF-FLEX-001",
    "WIF-KEY-001",
    "STS-REQ-001",
    "STS-ACTOR-001",
    "STS-TARGET-001",
    "STS-RIGHTS-001",
    "STS-LIFETIME-001",
    "OIDC-ISS-001",
    "OIDC-AUD-001",
    "OIDC-NONCE-001",
    "OIDC-TIME-001",
    "CKT-PARTIAL-001",
    "CKT-RODC-001",
    "CKT-LOS-001",
    "CKT-PRECEDENCE-001",
    "PAC-BOUNDS-001",
    "PAC-ORDER-001",
    "PAC-ATTR-001",
    "PAC-REQ-001",
    "PAC-SIG-001",
    "PAC-RODC-001",
    "PAC-TGS-001",
    "PAC-DLG-001",
    "DMSA-LINK-001",
    "DMSA-STATE-001",
    "DMSA-ACL-001",
    "DMSA-SPN-001",
    "DMSA-MACHINE-001",
    "DMSA-RWDC-001",
    "DMSA-EVENT-001",
    "DMSA-ROLLBACK-001",
}


def _valid_sources() -> dict[str, Any]:
    return {
        "RFC7523": {
            "title": "JSON Web Token Profile for OAuth 2.0 Client Authentication",
            "revision": "RFC 7523, May 2015",
            "primary_url": "https://datatracker.ietf.org/doc/html/rfc7523",
        }
    }


def _valid_rule(rule_id: str = "WIF-TYPE-001") -> dict[str, Any]:
    return {
        "id": rule_id,
        "source": "RFC7523",
        "section": "3",
        "summary": "Claims retain their specified JSON types.",
        "evidence_class": "spec-oracle",
        "positive_cases": [f"{rule_id.lower()}-valid"],
        "negative_cases": [f"{rule_id.lower()}-invalid"],
        "observe_cases": [],
    }


def _write_catalog(
    tmp_path: Path,
    *,
    rules: list[dict[str, Any]],
    sources: dict[str, Any] | None = None,
) -> Path:
    spec_dir = tmp_path / "spec"
    schema_dir = spec_dir / "schema"
    schema_dir.mkdir(parents=True)
    (spec_dir / "sources.yaml").write_text(
        yaml.safe_dump({"sources": sources or _valid_sources()}, sort_keys=False),
        encoding="utf-8",
    )
    schema = json.loads(
        (ROOT / "spec" / "schema" / "invariants.schema.json").read_text(
            encoding="utf-8"
        )
    )
    (schema_dir / "invariants.schema.json").write_text(
        json.dumps(schema), encoding="utf-8"
    )
    catalog_path = spec_dir / "invariants.yaml"
    catalog_path.write_text(
        yaml.safe_dump({"invariants": rules}, sort_keys=False), encoding="utf-8"
    )
    return catalog_path


def test_catalog_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    duplicate = _valid_rule()
    catalog_path = _write_catalog(tmp_path, rules=[duplicate, duplicate.copy()])

    with pytest.raises(ValueError, match="duplicate invariant ID"):
        load_catalog(catalog_path)


def test_catalog_rejects_unknown_evidence_class(tmp_path: Path) -> None:
    rule = _valid_rule()
    rule["evidence_class"] = "unclassified"
    catalog_path = _write_catalog(tmp_path, rules=[rule])

    with pytest.raises(ValueError, match="evidence_class"):
        load_catalog(catalog_path)


def test_catalog_requires_positive_and_negative_or_observe_cases(
    tmp_path: Path,
) -> None:
    rule = _valid_rule()
    rule["negative_cases"] = []
    catalog_path = _write_catalog(tmp_path, rules=[rule])

    with pytest.raises(ValueError, match="negative_cases or observe_cases"):
        load_catalog(catalog_path)


def test_catalog_sources_have_revision_and_primary_url(tmp_path: Path) -> None:
    sources = _valid_sources()
    sources["RFC7523"]["revision"] = ""
    catalog_path = _write_catalog(
        tmp_path, rules=[_valid_rule()], sources=sources
    )

    with pytest.raises(ValueError, match="revision"):
        load_catalog(catalog_path)


def test_catalog_contains_every_design_rule_id() -> None:
    rules = load_catalog(ROOT / "spec" / "invariants.yaml")

    validate_catalog_coverage(rules, DESIGN_RULE_IDS)
    assert {rule.id for rule in rules} == DESIGN_RULE_IDS
