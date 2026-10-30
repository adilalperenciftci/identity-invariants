from __future__ import annotations

from pathlib import Path

from identity_invariants.catalog import load_catalog
from identity_invariants.vectors.generator import canonical_digest, generate_cases


ROOT = Path(__file__).resolve().parents[2]


def test_identical_seed_produces_identical_case_ids() -> None:
    catalog = load_catalog(ROOT / "spec" / "invariants.yaml")

    first = generate_cases(20261030, catalog)
    second = generate_cases(20261030, catalog)

    assert first == second
    assert len({case.id for case in first}) == len(first)


def test_seed_changes_case_ids_without_changing_coverage() -> None:
    catalog = load_catalog(ROOT / "spec" / "invariants.yaml")
    first = generate_cases(1, catalog)
    second = generate_cases(2, catalog)

    assert {case.rule_id for case in first} == {case.rule_id for case in second}
    assert {case.id for case in first} != {case.id for case in second}


def test_canonical_digest_distinguishes_json_shapes() -> None:
    assert canonical_digest({"value": 1}) != canonical_digest({"value": "1"})
    assert canonical_digest(["a", "b"]) != canonical_digest({"0": "a", "1": "b"})
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})
