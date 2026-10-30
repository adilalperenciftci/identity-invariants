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
    GRANT_TYPE_INVALID = "grant_type_invalid"
    REQUEST_FIELD_REQUIRED = "request_field_required"
    PARAMETER_DUPLICATE = "parameter_duplicate"
    ACTOR_PAIR_INCOMPLETE = "actor_pair_incomplete"
    TOKEN_TYPE_NOT_ALLOWED = "token_type_not_allowed"
    TARGET_INVALID = "target_invalid"
    TARGET_DUPLICATE = "target_duplicate"
    SCOPE_INVALID = "scope_invalid"
    RIGHTS_NOT_ALLOWED = "rights_not_allowed"
    SUBJECT_REJECTED = "subject_rejected"
    ACTOR_REJECTED = "actor_rejected"
    TENANT_CONTEXT_MISSING = "tenant_context_missing"
    TENANT_CONTEXT_NOT_ALLOWED = "tenant_context_not_allowed"
    DISPOSABLE_APPLICATION_MISSING = "disposable_application_missing"
    AUTHORITY_HOST_NOT_ALLOWED = "authority_host_not_allowed"
    FIC_IDENTIFIER_MISSING = "fic_identifier_missing"
    DIRECTORY_ROLE_NOT_MINIMAL = "directory_role_not_minimal"
    REDACTION_PROBE_FAILED = "redaction_probe_failed"
    REQUEST_CEILING_INVALID = "request_ceiling_invalid"
    RUN_LABEL_MISSING = "run_label_missing"
    REQUEST_CEILING_REACHED = "request_ceiling_reached"
    OBSERVATION_RECORDED = "observation_recorded"
    RESPONSE_INVALID = "response_invalid"
    TRANSPORT_FAILED = "transport_failed"
    SERVER_2025_RWDC_MISSING = "server_2025_rwdc_missing"
    CLOUD_KERBEROS_OBJECT_MISSING = "cloud_kerberos_object_missing"
    PASSWORD_REPLICATION_POLICY_UNVERIFIED = (
        "password_replication_policy_unverified"
    )
    CLOUD_TRUST_POLICY_UNVERIFIED = "cloud_trust_policy_unverified"
    CERTIFICATE_TRUST_PRECEDENCE = "certificate_trust_precedence"
    WINDOWS_11_CLIENT_MISSING = "windows_11_client_missing"
    LINE_OF_SIGHT_MISSING = "line_of_sight_missing"
    PARTIAL_TGT_MISSING = "partial_tgt_missing"


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
