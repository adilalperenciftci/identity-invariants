"""Typed RFC 7523 and Entra federated credential decisions."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeAlias, cast

from identity_invariants.canonical import JSONValue, digest_identifier
from identity_invariants.clock import Clock, ReplayStore
from identity_invariants.decisions import Decision, ReasonCode


ReplayMode: TypeAlias = Literal["disabled", "observe", "enforce"]


class _ClaimError(ValueError):
    def __init__(self, reason: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def parse_numeric_date(value: JSONValue, claim: str) -> int:
    """Parse an integral NumericDate while excluding JSON booleans."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{claim} must be a NumericDate number")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError(f"{claim} NumericDate must be finite and integral")
    return int(value)


def _required_string(claims: Mapping[str, JSONValue], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str):
        raise _ClaimError(ReasonCode.CLAIM_TYPE_INVALID, f"{name} must be a string")
    return value


def _audiences(value: JSONValue) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return tuple(cast(list[str], value))
    raise _ClaimError(
        ReasonCode.CLAIM_TYPE_INVALID,
        "aud must be a string or non-empty string array",
    )


def _optional_numeric_date(
    claims: Mapping[str, JSONValue], name: str
) -> int | None:
    if name not in claims:
        return None
    try:
        return parse_numeric_date(claims[name], name)
    except ValueError as error:
        raise _ClaimError(ReasonCode.CLAIM_TYPE_INVALID, str(error)) from error


@dataclass(frozen=True, slots=True)
class TypedClaims:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    expiration: int
    not_before: int | None
    issued_at: int | None
    jwt_id: str | None
    raw: Mapping[str, JSONValue]

    @classmethod
    def from_mapping(cls, claims: Mapping[str, JSONValue]) -> "TypedClaims":
        issuer = _required_string(claims, "iss")
        subject = _required_string(claims, "sub")
        audience = _audiences(claims.get("aud"))
        if "exp" not in claims or claims.get("exp") is None:
            raise _ClaimError(
                ReasonCode.EXPIRATION_REQUIRED, "exp is required"
            )
        try:
            expiration = parse_numeric_date(claims["exp"], "exp")
        except ValueError as error:
            raise _ClaimError(ReasonCode.CLAIM_TYPE_INVALID, str(error)) from error
        not_before = _optional_numeric_date(claims, "nbf")
        issued_at = _optional_numeric_date(claims, "iat")
        raw_jti = claims.get("jti")
        if raw_jti is not None and not isinstance(raw_jti, str):
            raise _ClaimError(ReasonCode.CLAIM_TYPE_INVALID, "jti must be a string")
        return cls(
            issuer=issuer,
            subject=subject,
            audience=audience,
            expiration=expiration,
            not_before=not_before,
            issued_at=issued_at,
            jwt_id=cast(str | None, raw_jti),
            raw=MappingProxyType(dict(claims)),
        )


@dataclass(frozen=True, slots=True)
class AssertionProfile:
    allowed_algorithms: frozenset[str]
    clock_skew: int
    max_iat_age: int
    max_iat_future: int
    replay_mode: ReplayMode

    def __post_init__(self) -> None:
        if min(self.clock_skew, self.max_iat_age, self.max_iat_future) < 0:
            raise ValueError("assertion time limits cannot be negative")


@dataclass(frozen=True, slots=True)
class AssertionContext:
    expected_issuer: str
    expected_audience: str
    algorithm: str
    key_id: str
    trusted_key_ids: frozenset[str]
    signature_valid: bool
    profile: AssertionProfile
    replay_store: ReplayStore


@dataclass(frozen=True, slots=True)
class StandardCredential:
    issuer: str
    subject: str
    audiences: frozenset[str]


@dataclass(frozen=True, slots=True)
class FlexibleCredential:
    issuer: str
    audience: str
    claim_name: str
    claim_pattern: str
    immutable_claims: frozenset[str]


def _decision(
    outcome: Literal["accept", "reject", "observe"],
    rule_id: str,
    reason: ReasonCode,
    detail: str = "",
) -> Decision:
    return Decision(outcome=outcome, rule_id=rule_id, reason=reason, detail=detail)


def validate_client_assertion(
    claims: Mapping[str, JSONValue], context: AssertionContext, clock: Clock
) -> Decision:
    """Validate key metadata, typed claims, time, and profile replay policy."""

    profile = context.profile
    if context.algorithm not in profile.allowed_algorithms:
        return _decision("reject", "WIF-KEY-001", ReasonCode.ALGORITHM_NOT_ALLOWED)
    if context.key_id not in context.trusted_key_ids:
        return _decision("reject", "WIF-KEY-001", ReasonCode.KEY_NOT_TRUSTED)
    if not context.signature_valid:
        return _decision("reject", "WIF-KEY-001", ReasonCode.SIGNATURE_INVALID)

    try:
        typed = TypedClaims.from_mapping(claims)
    except _ClaimError as error:
        rule_id = "WIF-TIME-001" if error.reason is ReasonCode.EXPIRATION_REQUIRED else "WIF-TYPE-001"
        return _decision("reject", rule_id, error.reason, str(error))

    if typed.issuer != context.expected_issuer:
        return _decision("reject", "WIF-MATCH-001", ReasonCode.ISSUER_MISMATCH)
    if frozenset(typed.audience) != frozenset({context.expected_audience}):
        return _decision("reject", "WIF-MATCH-001", ReasonCode.AUDIENCE_MISMATCH)

    now = clock.now()
    if typed.expiration + profile.clock_skew <= now:
        return _decision("reject", "WIF-TIME-001", ReasonCode.EXPIRED)
    if typed.not_before is not None and typed.not_before > now + profile.clock_skew:
        return _decision("reject", "WIF-TIME-001", ReasonCode.NOT_YET_VALID)
    if typed.issued_at is not None:
        earliest = now - profile.max_iat_age - profile.clock_skew
        latest = now + profile.max_iat_future + profile.clock_skew
        if typed.issued_at < earliest or typed.issued_at > latest:
            return _decision(
                "reject", "WIF-TIME-001", ReasonCode.ISSUED_AT_OUT_OF_RANGE
            )

    if profile.replay_mode == "disabled":
        return _decision("accept", "WIF-TYPE-001", ReasonCode.ACCEPTED)
    if typed.jwt_id is None:
        if profile.replay_mode == "enforce":
            return _decision("reject", "WIF-REPLAY-001", ReasonCode.JTI_REQUIRED)
        return _decision("accept", "WIF-REPLAY-001", ReasonCode.ACCEPTED)

    namespace = f"{context.expected_issuer}|{context.expected_audience}"
    digest = digest_identifier(namespace, typed.jwt_id)
    fresh = context.replay_store.consume(
        namespace, digest, typed.expiration + profile.clock_skew, now
    )
    if fresh:
        return _decision("accept", "WIF-REPLAY-001", ReasonCode.ACCEPTED)
    if profile.replay_mode == "observe":
        return _decision(
            "observe", "WIF-REPLAY-001", ReasonCode.JTI_REPEAT_OBSERVED
        )
    return _decision("reject", "WIF-REPLAY-001", ReasonCode.JTI_REPLAY)


def match_standard_credential(
    credential: StandardCredential, claims: TypedClaims
) -> Decision:
    """Match the complete standard credential tuple without normalization."""

    if claims.issuer != credential.issuer:
        return _decision("reject", "WIF-MATCH-001", ReasonCode.ISSUER_MISMATCH)
    if claims.subject != credential.subject:
        return _decision("reject", "WIF-MATCH-001", ReasonCode.SUBJECT_MISMATCH)
    if frozenset(claims.audience) != credential.audiences:
        return _decision("reject", "WIF-MATCH-001", ReasonCode.AUDIENCE_MISMATCH)
    return _decision("accept", "WIF-MATCH-001", ReasonCode.ACCEPTED)


def _matches_single_wildcard(pattern: str, value: str) -> bool | None:
    if pattern.count("*") > 1:
        return None
    if "*" not in pattern:
        return value == pattern
    prefix, suffix = pattern.split("*", 1)
    return value.startswith(prefix) and value.endswith(suffix)


def match_flexible_credential(
    credential: FlexibleCredential, claims: TypedClaims
) -> Decision:
    """Evaluate a restricted wildcard expression anchored to an immutable claim."""

    if claims.issuer != credential.issuer:
        return _decision("reject", "WIF-FLEX-001", ReasonCode.ISSUER_MISMATCH)
    if frozenset(claims.audience) != frozenset({credential.audience}):
        return _decision("reject", "WIF-FLEX-001", ReasonCode.AUDIENCE_MISMATCH)
    if credential.claim_name not in credential.immutable_claims:
        return _decision("reject", "WIF-FLEX-001", ReasonCode.MUTABLE_CLAIM)
    value = claims.raw.get(credential.claim_name)
    if not isinstance(value, str):
        return _decision("reject", "WIF-FLEX-001", ReasonCode.CLAIM_TYPE_INVALID)
    matches = _matches_single_wildcard(credential.claim_pattern, value)
    if matches is None:
        return _decision(
            "reject", "WIF-FLEX-001", ReasonCode.INVALID_CLAIM_EXPRESSION
        )
    if not matches:
        return _decision(
            "reject", "WIF-FLEX-001", ReasonCode.CLAIM_EXPRESSION_MISMATCH
        )
    return _decision("accept", "WIF-FLEX-001", ReasonCode.ACCEPTED)
