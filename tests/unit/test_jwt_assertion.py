from __future__ import annotations

from dataclasses import replace

import pytest

from identity_invariants.canonical import parse_json_object
from identity_invariants.clock import FrozenClock, ReplayStore
from identity_invariants.decisions import ReasonCode
from identity_invariants.oracle.jwt_assertion import (
    AssertionContext,
    AssertionProfile,
    FlexibleCredential,
    StandardCredential,
    TypedClaims,
    match_flexible_credential,
    match_standard_credential,
    validate_client_assertion,
)


NOW = 1_800_000_000


def _profile(*, replay_mode: str = "observe") -> AssertionProfile:
    return AssertionProfile(
        allowed_algorithms=frozenset({"RS256"}),
        clock_skew=0,
        max_iat_age=300,
        max_iat_future=0,
        replay_mode=replay_mode,
    )


def _context(*, replay_mode: str = "observe") -> AssertionContext:
    return AssertionContext(
        expected_issuer="https://issuer.example/tenant",
        expected_audience="api://AzureADTokenExchange",
        algorithm="RS256",
        key_id="key-1",
        trusted_key_ids=frozenset({"key-1"}),
        signature_valid=True,
        profile=_profile(replay_mode=replay_mode),
        replay_store=ReplayStore(),
    )


def _claims(**changes: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": "https://issuer.example/tenant",
        "sub": "repo:org/project:ref:refs/heads/main",
        "aud": "api://AzureADTokenExchange",
        "exp": NOW + 60,
        "nbf": NOW - 1,
        "iat": NOW,
        "jti": "assertion-1",
    }
    claims.update(changes)
    return claims


def test_client_assertion_accepts_exact_typed_claims() -> None:
    decision = validate_client_assertion(_claims(), _context(), FrozenClock(NOW))

    assert decision.outcome == "accept"
    assert decision.reason is ReasonCode.ACCEPTED


def test_key_metadata_is_checked_before_claim_policy() -> None:
    context = replace(_context(), algorithm="none", signature_valid=False)

    decision = validate_client_assertion(
        _claims(iss=None, exp=None), context, FrozenClock(NOW)
    )

    assert decision.outcome == "reject"
    assert decision.reason is ReasonCode.ALGORITHM_NOT_ALLOWED


@pytest.mark.parametrize(
    "issuer",
    [
        "https://ISSUER.example/tenant",
        "https://issuer.example/tenant/",
        "https://issuer.example/%74enant",
        " https://issuer.example/tenant",
        "https://issuer.example/ten\u00e1nt",
        "https://issuer.example/tena\u0301nt",
    ],
)
def test_client_assertion_does_not_normalize_issuer(issuer: str) -> None:
    decision = validate_client_assertion(
        _claims(iss=issuer), _context(), FrozenClock(NOW)
    )

    assert decision.outcome == "reject"
    assert decision.reason is ReasonCode.ISSUER_MISMATCH


def test_standard_credential_matches_exact_tuple() -> None:
    typed = TypedClaims.from_mapping(_claims())
    credential = StandardCredential(
        issuer="https://issuer.example/tenant",
        subject="repo:org/project:ref:refs/heads/main",
        audiences=frozenset({"api://AzureADTokenExchange"}),
    )

    assert match_standard_credential(credential, typed).outcome == "accept"
    changed = replace(credential, subject=credential.subject.upper())
    assert match_standard_credential(changed, typed).outcome == "reject"


def test_flexible_credential_requires_immutable_claim_anchor() -> None:
    typed = TypedClaims.from_mapping(
        _claims(repository_id="987654", repository="org/project")
    )
    credential = FlexibleCredential(
        issuer="https://issuer.example/tenant",
        audience="api://AzureADTokenExchange",
        claim_name="repository_id",
        claim_pattern="987*",
        immutable_claims=frozenset({"repository_id"}),
    )

    assert match_flexible_credential(credential, typed).outcome == "accept"
    mutable = replace(credential, claim_name="repository", claim_pattern="org/*")
    assert match_flexible_credential(mutable, typed).reason is ReasonCode.MUTABLE_CLAIM


def test_duplicate_json_members_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate JSON member: iss"):
        parse_json_object('{"iss":"first","iss":"second"}')


def test_repeated_jti_is_observed_or_enforced_by_profile() -> None:
    observe_context = _context(replay_mode="observe")
    first = validate_client_assertion(_claims(), observe_context, FrozenClock(NOW))
    second = validate_client_assertion(_claims(), observe_context, FrozenClock(NOW))
    assert first.outcome == "accept"
    assert second.outcome == "observe"
    assert second.reason is ReasonCode.JTI_REPEAT_OBSERVED

    enforce_context = _context(replay_mode="enforce")
    first = validate_client_assertion(_claims(), enforce_context, FrozenClock(NOW))
    second = validate_client_assertion(_claims(), enforce_context, FrozenClock(NOW))
    assert first.outcome == "accept"
    assert second.outcome == "reject"
    assert second.reason is ReasonCode.JTI_REPLAY
