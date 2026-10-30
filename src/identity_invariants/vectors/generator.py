"""Stable case generation from the invariant catalog."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, TypeAlias

from identity_invariants.canonical import JSONValue
from identity_invariants.decisions import InvariantRule


CaseKind: TypeAlias = Literal["positive", "negative", "observe"]


@dataclass(frozen=True, slots=True)
class TestCase:
    id: str
    rule_id: str
    kind: CaseKind
    source_case: str
    seed: int


def canonical_digest(value: JSONValue) -> str:
    """Hash the canonical JSON representation, retaining JSON type distinctions."""

    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def generate_cases(
    seed: int, catalog: Sequence[InvariantRule]
) -> tuple[TestCase, ...]:
    """Generate stable case identities without pseudo-random global state."""

    cases: list[TestCase] = []
    for rule in sorted(catalog, key=lambda item: item.id):
        groups: tuple[tuple[CaseKind, tuple[str, ...]], ...] = (
            ("positive", rule.positive_cases),
            ("negative", rule.negative_cases),
            ("observe", rule.observe_cases),
        )
        for kind, names in groups:
            for name in names:
                digest = canonical_digest(
                    {
                        "seed": seed,
                        "rule_id": rule.id,
                        "kind": kind,
                        "source_case": name,
                    }
                )
                cases.append(
                    TestCase(
                        id=f"{rule.id.lower()}-{kind}-{digest[:16]}",
                        rule_id=rule.id,
                        kind=kind,
                        source_case=name,
                        seed=seed,
                    )
                )
    return tuple(cases)
