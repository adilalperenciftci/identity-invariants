from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = {
    "accesstoken",
    "password",
    "privatekey",
    "rawticket",
    "refreshtoken",
    "sessionkey",
    "credential",
}


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _assert_redacted(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalized_key(key)
            assert not any(part in normalized for part in _FORBIDDEN_KEYS)
            _assert_redacted(item)
    elif isinstance(value, list):
        for item in value:
            _assert_redacted(item)


def test_windows_dmsa_evidence_is_sealed_and_redacted() -> None:
    configured = os.environ.get("DMSA_EVIDENCE_DIR")
    if configured is None:
        pytest.skip("DMSA_EVIDENCE_DIR is set only for the isolated Windows run")
    root = Path(configured)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    ledger_path = root / manifest["ledger"]

    assert ledger_path.is_file()
    assert _DIGEST.fullmatch(manifest["ledger_sha256"])
    assert _digest(ledger_path) == manifest["ledger_sha256"]
    records = [
        json.loads(line)
        for line in ledger_path.read_text(encoding="utf-8-sig").splitlines()
    ]
    assert len(records) == manifest["record_count"]
    assert records
    artifact_digests = records[0]["artifact_digests"]
    assert artifact_digests
    for record in records:
        assert record["schema_version"] == 1
        assert record["adapter"] == "windows-dmsa"
        assert record["evidence_class"] == "windows-observation"
        assert record["outcome"] in {
            "accept",
            "reject",
            "observe",
            "skip",
            "inconclusive",
        }
        assert record["invariant_ids"]
        assert _DIGEST.fullmatch(record["before_digest"])
        assert _DIGEST.fullmatch(record["after_digest"])
        assert record["artifact_digests"] == artifact_digests
        for digest in artifact_digests.values():
            assert _DIGEST.fullmatch(digest)
        _assert_redacted(record)
    artifact_root = root / "artifacts"
    for name, expected_digest in artifact_digests.items():
        assert Path(name).name == name
        artifact_path = artifact_root / name
        assert artifact_path.is_file()
        assert _digest(artifact_path) == expected_digest
        _assert_redacted(
            json.loads(artifact_path.read_text(encoding="utf-8-sig"))
        )
