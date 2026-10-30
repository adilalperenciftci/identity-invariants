from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from identity_invariants.decisions import Decision, ReasonCode
from identity_invariants.oracle.token_exchange import (
    TOKEN_EXCHANGE_GRANT,
    JWT_BEARER_ASSERTION_TYPE,
    Target,
    TokenIdentity,
    TokenExchangePolicy,
    parse_entra_wif_form,
    parse_token_exchange_form,
    requested_rights,
    validate_token_exchange,
)


ROOT = Path(__file__).resolve().parents[2]
ACCEPT = Decision("accept", "WIF-TYPE-001", ReasonCode.ACCEPTED)
REJECT = Decision("reject", "WIF-TYPE-001", ReasonCode.CLAIM_TYPE_INVALID)


def _form(*extra: tuple[str, str]) -> list[tuple[str, str]]:
    return [
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", "subject-token"),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", "https://api.example/resource"),
        ("audience", "api-audience"),
        ("scope", "read write"),
        *extra,
    ]


def _policy() -> TokenExchangePolicy:
    targets = {
        Target("resource", "https://api.example/resource"),
        Target("audience", "api-audience"),
    }
    return TokenExchangePolicy(
        allowed_subject_token_types=frozenset(
            {"urn:ietf:params:oauth:token-type:jwt"}
        ),
        allowed_actor_token_types=frozenset(
            {"urn:ietf:params:oauth:token-type:jwt"}
        ),
        allowed_rights=frozenset(
            (target, scope) for target in targets for scope in ("read", "write")
        ),
    )


def test_parser_preserves_repeated_resources_and_audiences() -> None:
    request = parse_token_exchange_form(
        _form(
            ("resource", "https://second.example/service"),
            ("audience", "second-audience"),
        )
    )

    assert request.resources == (
        "https://api.example/resource",
        "https://second.example/service",
    )
    assert request.audiences == ("api-audience", "second-audience")
    assert request.scopes == ("read", "write")


@pytest.mark.parametrize(
    "missing", ["grant_type", "subject_token", "subject_token_type"]
)
def test_parser_requires_subject_request_fields(missing: str) -> None:
    items = [item for item in _form() if item[0] != missing]

    with pytest.raises(ValueError, match=missing):
        parse_token_exchange_form(items)


def test_parser_rejects_duplicate_singleton_parameter() -> None:
    with pytest.raises(ValueError, match="duplicate parameter: subject_token"):
        parse_token_exchange_form(_form(("subject_token", "other")))


@pytest.mark.parametrize(
    "actor_item",
    [
        ("actor_token", "actor-token"),
        ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
    ],
)
def test_actor_token_and_type_are_atomic(actor_item: tuple[str, str]) -> None:
    with pytest.raises(ValueError, match="actor_token and actor_token_type"):
        parse_token_exchange_form(_form(actor_item))


def test_requested_rights_is_complete_cartesian_product() -> None:
    request = parse_token_exchange_form(_form())

    assert requested_rights(request) == frozenset(
        {
            (Target("resource", "https://api.example/resource"), "read"),
            (Target("resource", "https://api.example/resource"), "write"),
            (Target("audience", "api-audience"), "read"),
            (Target("audience", "api-audience"), "write"),
        }
    )


def test_validation_rejects_silent_target_or_scope_loss() -> None:
    request = parse_token_exchange_form(_form())
    policy = _policy()
    narrowed = TokenExchangePolicy(
        allowed_subject_token_types=policy.allowed_subject_token_types,
        allowed_actor_token_types=policy.allowed_actor_token_types,
        allowed_rights=frozenset(
            right
            for right in policy.allowed_rights
            if right[0].kind == "resource" and right[1] == "read"
        ),
    )

    assert validate_token_exchange(request, policy, ACCEPT).outcome == "accept"
    decision = validate_token_exchange(request, narrowed, ACCEPT)
    assert decision.outcome == "reject"
    assert decision.reason is ReasonCode.RIGHTS_NOT_ALLOWED


def test_scope_matching_is_case_sensitive() -> None:
    items = [
        (name, "Read write" if name == "scope" else value)
        for name, value in _form()
    ]
    decision = validate_token_exchange(
        parse_token_exchange_form(items), _policy(), ACCEPT
    )

    assert decision.reason is ReasonCode.RIGHTS_NOT_ALLOWED


def test_subject_and_actor_decisions_remain_separate() -> None:
    request = parse_token_exchange_form(
        _form(
            ("actor_token", "actor-token"),
            ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        )
    )

    assert (
        validate_token_exchange(request, _policy(), REJECT, ACCEPT).reason
        is ReasonCode.SUBJECT_REJECTED
    )
    assert (
        validate_token_exchange(request, _policy(), ACCEPT, REJECT).reason
        is ReasonCode.ACTOR_REJECTED
    )


def test_actor_exchange_requires_distinct_normalized_identities() -> None:
    request = parse_token_exchange_form(
        _form(
            ("actor_token", "actor-token"),
            ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        )
    )
    subject = TokenIdentity("https://issuer.example", "workload-a")
    actor = TokenIdentity("https://issuer.example", "broker-b")

    missing = validate_token_exchange(request, _policy(), ACCEPT, ACCEPT)
    collapsed = validate_token_exchange(
        request,
        _policy(),
        ACCEPT,
        ACCEPT,
        subject_identity=subject,
        actor_identity=subject,
    )
    distinct = validate_token_exchange(
        request,
        _policy(),
        ACCEPT,
        ACCEPT,
        subject_identity=subject,
        actor_identity=actor,
    )

    assert missing.reason is ReasonCode.ACTOR_IDENTITY_REQUIRED
    assert collapsed.reason is ReasonCode.SUBJECT_ACTOR_COLLAPSED
    assert distinct.outcome == "accept"


def test_entra_wif_and_rfc8693_transport_profiles_are_distinct() -> None:
    entra_form = [
        ("grant_type", "client_credentials"),
        ("client_id", "client-123"),
        ("scope", "https://graph.microsoft.com/.default"),
        ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
        ("client_assertion", "assertion"),
    ]

    with pytest.raises(ValueError):
        parse_token_exchange_form(entra_form)
    with pytest.raises(ValueError):
        parse_entra_wif_form(_form())
    assert parse_entra_wif_form(entra_form).client_id == "client-123"


def test_reference_vectors_identify_both_profiles() -> None:
    document = yaml.safe_load(
        (ROOT / "vectors" / "token-exchange.yaml").read_text(encoding="utf-8")
    )

    assert {case["profile"] for case in document["cases"]} == {
        "rfc8693",
        "entra-wif",
    }
