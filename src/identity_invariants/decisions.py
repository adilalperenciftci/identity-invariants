"""Shared decision and catalog types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, TypeAlias


DecisionClass: TypeAlias = Literal[
    "accept", "reject", "observe", "skip", "inconclusive"
]
EvidenceClass: TypeAlias = Literal[
    "spec-oracle", "local-adapter", "windows-observation", "entra-observation"
]


class ReasonCode(StrEnum):
    """Stable reason codes shared by validators and evidence records."""

    CATALOG_INVALID = "catalog_invalid"
    CATALOG_COVERAGE_MISSING = "catalog_coverage_missing"


@dataclass(frozen=True, slots=True)
class InvariantRule:
    """One normalized invariant with its source and case bindings."""

    id: str
    source: str
    source_title: str
    source_revision: str
    source_primary_url: str
    section: str
    summary: str
    evidence_class: EvidenceClass
    positive_cases: tuple[str, ...]
    negative_cases: tuple[str, ...]
    observe_cases: tuple[str, ...]
