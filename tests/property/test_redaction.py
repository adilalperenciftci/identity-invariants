from __future__ import annotations

from pathlib import Path

import pytest

from identity_invariants.decisions import ReasonCode
from identity_invariants.evidence.ledger import EvidenceRecord, EvidenceWriter


def _record(metadata: dict[str, object]) -> EvidenceRecord:
    return EvidenceRecord(
        case_id="case-redaction",
        rule_id="OIDC-NONCE-001",
        outcome="reject",
        reason=ReasonCode.NONCE_MISMATCH,
        evidence_class="spec-oracle",
        input_digest="a" * 64,
        artifact_digests={},
        metadata=metadata,
    )


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "client_secret",
        "access_token",
        "refreshToken",
        "private_key",
        "client_assertion",
        "kerberos_ticket",
    ],
)
def test_secret_like_metadata_keys_are_rejected(tmp_path: Path, key: str) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")

    with pytest.raises(ValueError, match="prohibited metadata key"):
        writer.append(_record({key: "redacted"}))


@pytest.mark.parametrize(
    "value",
    [
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
    ],
)
def test_assertion_or_key_shaped_values_are_rejected(
    tmp_path: Path, value: str
) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")

    with pytest.raises(ValueError, match="prohibited value shape"):
        writer.append(_record({"observation": value}))


def test_normalized_metadata_shape_is_accepted(tmp_path: Path) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    writer.append(
        _record(
            {
                "profile": "oidc-core",
                "claim_names": ["iss", "aud", "exp"],
                "clock_skew_seconds": 30,
                "signature_verified": True,
            }
        )
    )

    assert writer.seal().record_count == 1
