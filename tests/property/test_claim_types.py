from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from identity_invariants.clock import FrozenClock, ReplayStore
from identity_invariants.oracle.jwt_assertion import (
    AssertionContext,
    AssertionProfile,
    parse_numeric_date,
    validate_client_assertion,
)


NOW = 1_800_000_000


def _context() -> AssertionContext:
    return AssertionContext(
        expected_issuer="issuer",
        expected_audience="audience",
        algorithm="RS256",
        key_id="key-1",
        trusted_key_ids=frozenset({"key-1"}),
        signature_valid=True,
        profile=AssertionProfile(
            allowed_algorithms=frozenset({"RS256"}),
            clock_skew=0,
            max_iat_age=300,
            max_iat_future=0,
            replay_mode="disabled",
        ),
        replay_store=ReplayStore(),
    )


@settings(max_examples=40, derandomize=True)
@given(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.lists(st.text(), max_size=2),
        st.dictionaries(st.text(max_size=3), st.integers(), max_size=2),
    )
)
def test_issuer_and_subject_reject_non_strings(value: object) -> None:
    base: dict[str, object] = {
        "iss": "issuer",
        "sub": "subject",
        "aud": "audience",
        "exp": NOW + 10,
        "iat": NOW,
    }
    for claim in ("iss", "sub"):
        claims = dict(base)
        claims[claim] = value
        assert (
            validate_client_assertion(claims, _context(), FrozenClock(NOW)).outcome
            == "reject"
        )


@pytest.mark.parametrize("value", [True, False, None, "1800000000", [], {}])
def test_numeric_date_rejects_boolean_and_non_numbers(value: object) -> None:
    with pytest.raises(ValueError, match="NumericDate"):
        parse_numeric_date(value, "exp")  # type: ignore[arg-type]


def test_numeric_date_accepts_integral_json_numbers() -> None:
    assert parse_numeric_date(42, "exp") == 42
    assert parse_numeric_date(42.0, "exp") == 42
    with pytest.raises(ValueError, match="integral"):
        parse_numeric_date(42.5, "exp")
