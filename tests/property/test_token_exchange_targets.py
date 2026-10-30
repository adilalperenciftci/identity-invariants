from __future__ import annotations

from hypothesis import given, settings, strategies as st

from identity_invariants.decisions import Decision, ReasonCode
from identity_invariants.oracle.token_exchange import (
    TOKEN_EXCHANGE_GRANT,
    Target,
    TokenExchangePolicy,
    parse_token_exchange_form,
    validate_token_exchange,
)


ACCEPT = Decision("accept", "WIF-TYPE-001", ReasonCode.ACCEPTED)


def _request(resource: str):
    return parse_token_exchange_form(
        [
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", "subject-token"),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("resource", resource),
            ("scope", "read"),
        ]
    )


def _policy(resource: str) -> TokenExchangePolicy:
    return TokenExchangePolicy(
        allowed_subject_token_types=frozenset(
            {"urn:ietf:params:oauth:token-type:jwt"}
        ),
        allowed_actor_token_types=frozenset(),
        allowed_rights=frozenset({(Target("resource", resource), "read")}),
    )


@settings(max_examples=40, derandomize=True)
@given(
    st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"),
            whitelist_characters="-_",
            min_codepoint=32,
            max_codepoint=126,
        ),
        min_size=1,
        max_size=20,
    )
)
def test_absolute_fragment_free_resource_is_accepted(segment: str) -> None:
    resource = f"https://api.example/{segment}"
    decision = validate_token_exchange(_request(resource), _policy(resource), ACCEPT)

    assert decision.outcome == "accept"


@settings(max_examples=30, derandomize=True)
@given(st.sampled_from(["relative/path", "/absolute-path", "https://api.example/x#part"]))
def test_relative_or_fragmented_resource_is_rejected(resource: str) -> None:
    decision = validate_token_exchange(_request(resource), _policy(resource), ACCEPT)

    assert decision.outcome == "reject"
    assert decision.reason is ReasonCode.TARGET_INVALID
