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
    ACCEPTED = "accepted"
    ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
    KEY_NOT_TRUSTED = "key_not_trusted"
    SIGNATURE_INVALID = "signature_invalid"
    CLAIM_TYPE_INVALID = "claim_type_invalid"
    ISSUER_MISMATCH = "issuer_mismatch"
    SUBJECT_MISMATCH = "subject_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    UNTRUSTED_AUDIENCE = "untrusted_audience"
    EXPIRATION_REQUIRED = "expiration_required"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    ISSUED_AT_OUT_OF_RANGE = "issued_at_out_of_range"
    JTI_REQUIRED = "jti_required"
    JTI_REPLAY = "jti_replay"
    JTI_REPEAT_OBSERVED = "jti_repeat_observed"
    MUTABLE_CLAIM = "mutable_claim"
    INVALID_CLAIM_EXPRESSION = "invalid_claim_expression"
    CLAIM_EXPRESSION_MISMATCH = "claim_expression_mismatch"
    NONCE_MISSING = "nonce_missing"
    NONCE_MISMATCH = "nonce_mismatch"
    NONCE_REPLAY_OR_EXPIRED = "nonce_replay_or_expired"


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


@dataclass(frozen=True, slots=True)
class Decision:
    """Normalized result emitted by every protocol state machine."""

    outcome: DecisionClass
    rule_id: str
    reason: ReasonCode
    detail: str = ""
