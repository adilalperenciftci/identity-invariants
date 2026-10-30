from __future__ import annotations

from identity_invariants.clock import FrozenClock, NonceStore
from identity_invariants.decisions import ReasonCode
from identity_invariants.oracle.oidc import OIDCContext, validate_id_token_claims


NOW = 1_800_000_000


def _claims(**changes: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": "https://issuer.example/tenant",
        "sub": "user-123",
        "aud": "client-123",
        "exp": NOW + 60,
        "iat": NOW,
        "nonce": "nonce-123",
    }
    claims.update(changes)
    return claims


def _context(**changes: object) -> OIDCContext:
    values: dict[str, object] = {
        "expected_issuer": "https://issuer.example/tenant",
        "client_id": "client-123",
        "trusted_audiences": frozenset({"client-123", "api://trusted"}),
        "expected_nonce": "nonce-123",
        "nonce_namespace": "login-session-1",
        "clock_skew": 0,
    }
    values.update(changes)
    return OIDCContext(**values)  # type: ignore[arg-type]


def _nonce_store(*, expires_at: int = NOW + 60) -> NonceStore:
    store = NonceStore()
    store.remember("login-session-1", "nonce-123", expires_at)
    return store


def test_oidc_accepts_exact_issuer_client_and_fresh_nonce() -> None:
    decision = validate_id_token_claims(
        _claims(), _context(), _nonce_store(), FrozenClock(NOW)
    )

    assert decision.outcome == "accept"


def test_oidc_rejects_untrusted_additional_audience() -> None:
    decision = validate_id_token_claims(
        _claims(aud=["client-123", "api://untrusted"]),
        _context(),
        _nonce_store(),
        FrozenClock(NOW),
    )

    assert decision.reason is ReasonCode.UNTRUSTED_AUDIENCE


def test_oidc_requires_sent_nonce_to_be_present_and_equal() -> None:
    missing = _claims()
    missing.pop("nonce")
    assert (
        validate_id_token_claims(
            missing, _context(), _nonce_store(), FrozenClock(NOW)
        ).reason
        is ReasonCode.NONCE_MISSING
    )
    assert (
        validate_id_token_claims(
            _claims(nonce="different"),
            _context(),
            _nonce_store(),
            FrozenClock(NOW),
        ).reason
        is ReasonCode.NONCE_MISMATCH
    )


def test_oidc_nonce_is_consumed_once() -> None:
    store = _nonce_store()
    first = validate_id_token_claims(_claims(), _context(), store, FrozenClock(NOW))
    second = validate_id_token_claims(_claims(), _context(), store, FrozenClock(NOW))

    assert first.outcome == "accept"
    assert second.outcome == "reject"
    assert second.reason is ReasonCode.NONCE_REPLAY_OR_EXPIRED


def test_oidc_nonce_expiry_uses_injected_clock() -> None:
    decision = validate_id_token_claims(
        _claims(), _context(), _nonce_store(expires_at=NOW), FrozenClock(NOW)
    )

    assert decision.outcome == "reject"
    assert decision.reason is ReasonCode.NONCE_REPLAY_OR_EXPIRED


def test_oidc_issuer_and_client_audience_are_exact() -> None:
    issuer = validate_id_token_claims(
        _claims(iss="https://issuer.example/tenant/"),
        _context(),
        _nonce_store(),
        FrozenClock(NOW),
    )
    audience = validate_id_token_claims(
        _claims(aud="CLIENT-123"),
        _context(),
        _nonce_store(),
        FrozenClock(NOW),
    )

    assert issuer.reason is ReasonCode.ISSUER_MISMATCH
    assert audience.reason is ReasonCode.AUDIENCE_MISMATCH
