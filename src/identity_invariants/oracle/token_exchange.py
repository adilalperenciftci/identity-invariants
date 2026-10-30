"""Strict RFC 8693 and Entra workload transport profile models."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TypeAlias
from urllib.parse import urlparse

from identity_invariants.decisions import Decision, ReasonCode


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TargetKind: TypeAlias = Literal["resource", "audience"]
Scope: TypeAlias = str


@dataclass(frozen=True, slots=True, order=True)
class Target:
    kind: TargetKind
    value: str


@dataclass(frozen=True, slots=True)
class TokenExchangeRequest:
    grant_type: str
    subject_token: str
    subject_token_type: str
    actor_token: str | None
    actor_token_type: str | None
    resources: tuple[str, ...]
    audiences: tuple[str, ...]
    scopes: tuple[str, ...]
    requested_token_type: str | None
    raw_items: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class EntraWIFRequest:
    grant_type: str
    client_id: str
    scope: str
    client_assertion_type: str
    client_assertion: str


@dataclass(frozen=True, slots=True)
class TokenExchangePolicy:
    allowed_subject_token_types: frozenset[str]
    allowed_actor_token_types: frozenset[str]
    allowed_rights: frozenset[tuple[Target, Scope]]


@dataclass(frozen=True, slots=True)
class TokenIdentity:
    issuer: str
    subject: str

    def __post_init__(self) -> None:
        if type(self.issuer) is not str or not self.issuer:
            raise ValueError("token identity issuer must be a non-empty string")
        if type(self.subject) is not str or not self.subject:
            raise ValueError("token identity subject must be a non-empty string")


def _group_form(items: Sequence[tuple[str, str]]) -> Mapping[str, list[str]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for name, value in items:
        if not name or not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("form parameters must be string name/value pairs")
        grouped[name].append(value)
    return grouped


def _singleton(
    grouped: Mapping[str, list[str]], name: str, *, required: bool = False
) -> str | None:
    values = grouped.get(name, [])
    if len(values) > 1:
        raise ValueError(f"duplicate parameter: {name}")
    if not values:
        if required:
            raise ValueError(f"required parameter missing: {name}")
        return None
    if not values[0]:
        raise ValueError(f"parameter cannot be empty: {name}")
    return values[0]


def parse_token_exchange_form(
    items: Sequence[tuple[str, str]],
) -> TokenExchangeRequest:
    """Parse RFC 8693 form items without collapsing repeatable targets."""

    grouped = _group_form(items)
    allowed = {
        "grant_type",
        "subject_token",
        "subject_token_type",
        "actor_token",
        "actor_token_type",
        "resource",
        "audience",
        "scope",
        "requested_token_type",
    }
    unexpected = sorted(set(grouped) - allowed)
    if unexpected:
        raise ValueError(f"unexpected token exchange parameter: {unexpected[0]}")

    grant_type = _singleton(grouped, "grant_type", required=True)
    if grant_type != TOKEN_EXCHANGE_GRANT:
        raise ValueError("grant_type is not the RFC 8693 token exchange grant")
    subject_token = _singleton(grouped, "subject_token", required=True)
    subject_token_type = _singleton(grouped, "subject_token_type", required=True)
    actor_token = _singleton(grouped, "actor_token")
    actor_token_type = _singleton(grouped, "actor_token_type")
    if (actor_token is None) != (actor_token_type is None):
        raise ValueError("actor_token and actor_token_type must occur together")
    scope_value = _singleton(grouped, "scope")
    scopes = tuple(scope_value.split()) if scope_value is not None else ()
    if scope_value is not None and not scopes:
        raise ValueError("scope must contain at least one value")
    return TokenExchangeRequest(
        grant_type=grant_type,
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        actor_token=actor_token,
        actor_token_type=actor_token_type,
        resources=tuple(grouped.get("resource", [])),
        audiences=tuple(grouped.get("audience", [])),
        scopes=scopes,
        requested_token_type=_singleton(grouped, "requested_token_type"),
        raw_items=tuple(items),
    )


def parse_entra_wif_form(items: Sequence[tuple[str, str]]) -> EntraWIFRequest:
    """Parse the distinct Entra JWT client-credentials transport profile."""

    grouped = _group_form(items)
    expected = {
        "grant_type",
        "client_id",
        "scope",
        "client_assertion_type",
        "client_assertion",
    }
    if set(grouped) != expected:
        missing = sorted(expected - set(grouped))
        unexpected = sorted(set(grouped) - expected)
        detail = missing[0] if missing else unexpected[0]
        raise ValueError(f"invalid Entra WIF parameter set: {detail}")
    values = {
        name: _singleton(grouped, name, required=True) for name in sorted(expected)
    }
    if values["grant_type"] != "client_credentials":
        raise ValueError("Entra WIF grant_type must be client_credentials")
    if values["client_assertion_type"] != JWT_BEARER_ASSERTION_TYPE:
        raise ValueError("Entra WIF client_assertion_type is invalid")
    scope = values["scope"]
    if (
        scope is None
        or not scope.endswith("/.default")
        or any(char.isspace() for char in scope)
    ):
        raise ValueError("Entra WIF scope must name one resource /.default scope")
    return EntraWIFRequest(
        grant_type=values["grant_type"],
        client_id=values["client_id"],
        scope=scope,
        client_assertion_type=values["client_assertion_type"],
        client_assertion=values["client_assertion"],
    )


def requested_rights(
    request: TokenExchangeRequest,
) -> frozenset[tuple[Target, Scope]]:
    """Return the complete target-by-scope rights product."""

    targets = tuple(Target("resource", value) for value in request.resources) + tuple(
        Target("audience", value) for value in request.audiences
    )
    return frozenset((target, scope) for target in targets for scope in request.scopes)


def _resource_is_absolute_and_fragment_free(value: str) -> bool:
    parsed = urlparse(value)
    if not parsed.scheme or parsed.fragment:
        return False
    if parsed.scheme in {"http", "https"} and not parsed.netloc:
        return False
    return True


def _reject(reason: ReasonCode, detail: str = "") -> Decision:
    return Decision("reject", "STS-REQ-001", reason, detail)


def validate_token_exchange(
    request: TokenExchangeRequest,
    policy: TokenExchangePolicy,
    subject_decision: Decision,
    actor_decision: Decision | None = None,
    *,
    subject_identity: TokenIdentity | None = None,
    actor_identity: TokenIdentity | None = None,
) -> Decision:
    """Validate the strict reference profile without narrowing requested rights."""

    if request.grant_type != TOKEN_EXCHANGE_GRANT:
        return _reject(ReasonCode.GRANT_TYPE_INVALID)
    if request.subject_token_type not in policy.allowed_subject_token_types:
        return _reject(ReasonCode.TOKEN_TYPE_NOT_ALLOWED, "subject token type")
    if subject_decision.outcome != "accept":
        return Decision("reject", "STS-REQ-001", ReasonCode.SUBJECT_REJECTED)
    if request.actor_token is not None:
        if request.actor_token_type not in policy.allowed_actor_token_types:
            return Decision(
                "reject", "STS-ACTOR-001", ReasonCode.TOKEN_TYPE_NOT_ALLOWED
            )
        if actor_decision is None or actor_decision.outcome != "accept":
            return Decision("reject", "STS-ACTOR-001", ReasonCode.ACTOR_REJECTED)
        if subject_identity is None or actor_identity is None:
            return Decision(
                "reject", "STS-ACTOR-001", ReasonCode.ACTOR_IDENTITY_REQUIRED
            )
        if subject_identity == actor_identity:
            return Decision(
                "reject", "STS-ACTOR-001", ReasonCode.SUBJECT_ACTOR_COLLAPSED
            )

    target_values = request.resources + request.audiences
    if not target_values:
        return Decision("reject", "STS-TARGET-001", ReasonCode.TARGET_INVALID)
    if len(set(request.resources)) != len(request.resources) or len(
        set(request.audiences)
    ) != len(request.audiences):
        return Decision("reject", "STS-TARGET-001", ReasonCode.TARGET_DUPLICATE)
    if set(request.resources) & set(request.audiences):
        return Decision("reject", "STS-TARGET-001", ReasonCode.TARGET_DUPLICATE)
    if any(
        not _resource_is_absolute_and_fragment_free(value)
        for value in request.resources
    ):
        return Decision("reject", "STS-TARGET-001", ReasonCode.TARGET_INVALID)
    if any(not value for value in request.audiences):
        return Decision("reject", "STS-TARGET-001", ReasonCode.TARGET_INVALID)
    if not request.scopes or len(set(request.scopes)) != len(request.scopes):
        return Decision("reject", "STS-RIGHTS-001", ReasonCode.SCOPE_INVALID)

    rights = requested_rights(request)
    if not rights.issubset(policy.allowed_rights):
        return Decision("reject", "STS-RIGHTS-001", ReasonCode.RIGHTS_NOT_ALLOWED)
    return Decision("accept", "STS-RIGHTS-001", ReasonCode.ACCEPTED)
