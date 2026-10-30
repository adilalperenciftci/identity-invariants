"""Append-only normalized evidence ledger with a sealed digest manifest."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from identity_invariants.canonical import JSONValue
from identity_invariants.decisions import DecisionClass, EvidenceClass, ReasonCode


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}$")
_PROHIBITED_KEY_PARTS = (
    "password",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "privatekey",
    "clientassertion",
    "kerberosticket",
    "rawassertion",
    "rawticket",
)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    case_id: str
    rule_id: str
    outcome: DecisionClass
    reason: ReasonCode
    evidence_class: EvidenceClass
    input_digest: str
    artifact_digests: Mapping[str, str]
    metadata: Mapping[str, JSONValue]


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    path: Path
    ledger: str
    ledger_sha256: str
    record_count: int
    format_version: int = 1


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_digest(value: str, field: str) -> None:
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _validate_redacted(value: JSONValue, path: str = "metadata") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if any(part in normalized for part in _PROHIBITED_KEY_PARTS):
                raise ValueError(f"prohibited metadata key: {path}.{key}")
            _validate_redacted(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_redacted(item, f"{path}[{index}]")
        return
    if isinstance(value, str) and (
        _JWT_SHAPE.fullmatch(value) or "-----BEGIN " in value or "-----END " in value
    ):
        raise ValueError(f"prohibited value shape: {path}")


class EvidenceWriter:
    """Write normalized JSONL records, then seal their exact byte representation."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(b"")
        self._record_count = 0
        self._sealed = False

    def append(self, record: EvidenceRecord) -> None:
        if self._sealed:
            raise RuntimeError("evidence writer is sealed")
        _validate_digest(record.input_digest, "input_digest")
        for name, digest in record.artifact_digests.items():
            if not name:
                raise ValueError("artifact digest name cannot be empty")
            _validate_digest(digest, f"artifact_digests.{name}")
        metadata = dict(record.metadata)
        _validate_redacted(metadata)
        document = asdict(record)
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.write("\n")
        self._record_count += 1

    def seal(self) -> EvidenceManifest:
        if self._sealed:
            raise RuntimeError("evidence writer is already sealed")
        self._sealed = True
        manifest_path = self._path.with_suffix(self._path.suffix + ".manifest.json")
        manifest = EvidenceManifest(
            path=manifest_path,
            ledger=self._path.name,
            ledger_sha256=_file_digest(self._path),
            record_count=self._record_count,
        )
        document = {
            "format_version": manifest.format_version,
            "ledger": manifest.ledger,
            "ledger_sha256": manifest.ledger_sha256,
            "record_count": manifest.record_count,
        }
        temporary = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(manifest_path)
        return manifest


def verify_manifest(path: Path) -> None:
    """Verify the ledger path, byte digest, and record count in one manifest."""

    document = json.loads(path.read_text(encoding="utf-8"))
    ledger_name = document.get("ledger")
    if not isinstance(ledger_name, str) or Path(ledger_name).name != ledger_name:
        raise ValueError("manifest ledger path must be a local filename")
    ledger_path = path.parent / ledger_name
    expected_digest = document.get("ledger_sha256")
    if not isinstance(expected_digest, str) or _file_digest(ledger_path) != expected_digest:
        raise ValueError("ledger digest mismatch")
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != document.get("record_count"):
        raise ValueError("ledger record count mismatch")
    for line in lines:
        json.loads(line)
