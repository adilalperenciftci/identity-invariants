from __future__ import annotations

from hypothesis import given, settings, strategies as st

from identity_invariants.clock import FrozenClock, ReplayStore
from identity_invariants.decisions import ReasonCode
from identity_invariants.oracle.jwt_assertion import (
    AssertionContext,
    AssertionProfile,
    validate_client_assertion,
)


NOW = 1_800_000_000


def _decision(**changes: object):
    claims: dict[str, object] = {
        "iss": "issuer",
        "sub": "subject",
        "aud": "audience",
        "exp": NOW + 1,
        "nbf": NOW,
        "iat": NOW,
    }
    claims.update(changes)
    context = AssertionContext(
        expected_issuer="issuer",
        expected_audience="audience",
        algorithm="RS256",
        key_id="key-1",
        trusted_key_ids=frozenset({"key-1"}),
        signature_valid=True,
        profile=AssertionProfile(
            allowed_algorithms=frozenset({"RS256"}),
            clock_skew=2,
            max_iat_age=300,
            max_iat_future=0,
            replay_mode="disabled",
        ),
        replay_store=ReplayStore(),
    )
    return validate_client_assertion(claims, context, FrozenClock(NOW))


def test_expiration_boundary_is_exclusive_after_skew() -> None:
    assert _decision(exp=NOW - 1).outcome == "accept"
    assert _decision(exp=NOW - 2).reason is ReasonCode.EXPIRED
    assert _decision(exp=NOW + 1).outcome == "accept"


def test_not_before_boundary_is_inclusive_with_skew() -> None:
    assert _decision(nbf=NOW + 2).outcome == "accept"
    assert _decision(nbf=NOW + 3).reason is ReasonCode.NOT_YET_VALID


def test_missing_expiration_is_rejected() -> None:
    assert _decision(exp=None).reason is ReasonCode.EXPIRATION_REQUIRED


def test_issued_at_rejects_far_past_and_future() -> None:
    assert _decision(iat=NOW - 302).outcome == "accept"
    assert _decision(iat=NOW - 303).reason is ReasonCode.ISSUED_AT_OUT_OF_RANGE
    assert _decision(iat=NOW + 2).outcome == "accept"
    assert _decision(iat=NOW + 3).reason is ReasonCode.ISSUED_AT_OUT_OF_RANGE


@settings(max_examples=50, derandomize=True)
@given(st.integers(min_value=-1000, max_value=1000))
def test_expiration_decision_matches_explicit_skew(delta: int) -> None:
    decision = _decision(exp=NOW + delta)
    assert (decision.outcome != "reject") is (delta > -2)
