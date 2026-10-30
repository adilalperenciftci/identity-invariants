"""OpenID Connect ID token claim and nonce decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from identity_invariants.canonical import JSONValue
from identity_invariants.clock import Clock, NonceStore
from identity_invariants.decisions import Decision, ReasonCode
from identity_invariants.oracle.jwt_assertion import (
    TypedClaims,
    _ClaimError,
    parse_numeric_date,
)


@dataclass(frozen=True, slots=True)
class OIDCContext:
    expected_issuer: str
    client_id: str
    trusted_audiences: frozenset[str]
    expected_nonce: str | None
    nonce_namespace: str
    clock_skew: int
    max_auth_age: int | None = None

    def __post_init__(self) -> None:
        if self.clock_skew < 0:
            raise ValueError("OIDC clock skew cannot be negative")
        if self.max_auth_age is not None and (
            type(self.max_auth_age) is not int or self.max_auth_age < 0
        ):
            raise ValueError("OIDC maximum authentication age is invalid")
        if self.client_id not in self.trusted_audiences:
            raise ValueError("trusted audiences must include the client ID")


def _reject(rule_id: str, reason: ReasonCode, detail: str = "") -> Decision:
    return Decision("reject", rule_id, reason, detail)


def validate_id_token_claims(
    claims: Mapping[str, JSONValue],
    context: OIDCContext,
    nonce_store: NonceStore,
    clock: Clock,
) -> Decision:
    """Validate exact issuer/audience, temporal bounds, and one-use nonce state."""

    try:
        typed = TypedClaims.from_mapping(claims)
    except _ClaimError as error:
        return _reject("OIDC-TIME-001", error.reason, str(error))

    if typed.issuer != context.expected_issuer:
        return _reject("OIDC-ISS-001", ReasonCode.ISSUER_MISMATCH)
    audiences = frozenset(typed.audience)
    if context.client_id not in audiences:
        return _reject("OIDC-AUD-001", ReasonCode.AUDIENCE_MISMATCH)
    if not audiences.issubset(context.trusted_audiences):
        return _reject("OIDC-AUD-001", ReasonCode.UNTRUSTED_AUDIENCE)

    now = clock.now()
    if typed.expiration + context.clock_skew <= now:
        return _reject("OIDC-TIME-001", ReasonCode.EXPIRED)
    if typed.issued_at is None or typed.issued_at > now + context.clock_skew:
        return _reject("OIDC-TIME-001", ReasonCode.ISSUED_AT_OUT_OF_RANGE)

    auth_time: int | None = None
    if "auth_time" in claims:
        try:
            auth_time = parse_numeric_date(claims["auth_time"], "auth_time")
        except ValueError as error:
            return _reject(
                "OIDC-TIME-001", ReasonCode.CLAIM_TYPE_INVALID, str(error)
            )
    if context.max_auth_age is not None and auth_time is None:
        return _reject("OIDC-TIME-001", ReasonCode.AUTH_TIME_REQUIRED)
    if auth_time is not None and (
        auth_time > now + context.clock_skew
        or (
            context.max_auth_age is not None
            and auth_time + context.max_auth_age + context.clock_skew < now
        )
    ):
        return _reject("OIDC-TIME-001", ReasonCode.AUTH_TIME_OUT_OF_RANGE)

    if context.expected_nonce is not None:
        nonce = claims.get("nonce")
        if nonce is None:
            return _reject("OIDC-NONCE-001", ReasonCode.NONCE_MISSING)
        if not isinstance(nonce, str) or nonce != context.expected_nonce:
            return _reject("OIDC-NONCE-001", ReasonCode.NONCE_MISMATCH)
        if not nonce_store.consume(context.nonce_namespace, nonce, now):
            return _reject(
                "OIDC-NONCE-001", ReasonCode.NONCE_REPLAY_OR_EXPIRED
            )

    return Decision("accept", "OIDC-NONCE-001", ReasonCode.ACCEPTED)
