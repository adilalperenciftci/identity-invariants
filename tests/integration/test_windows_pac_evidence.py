from __future__ import annotations

import json
import os
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from identity_invariants.adapters.windows_pac import normalize_windows_pac_observation


def _pac(*buffers: tuple[int, bytes]) -> bytes:
    table_size = 8 + 16 * len(buffers)
    offset = (table_size + 7) & ~7
    entries: list[tuple[int, int, int]] = []
    data = bytearray(offset)
    for type_id, payload in buffers:
        entries.append((type_id, len(payload), offset))
        data.extend(payload)
        offset += len(payload)
        padding = (-offset) % 8
        data.extend(b"\x00" * padding)
        offset += padding
    struct.pack_into("<II", data, 0, len(entries), 0)
    for index, entry in enumerate(entries):
        struct.pack_into("<IIQ", data, 8 + index * 16, *entry)
    return bytes(data)


def _sid() -> bytes:
    return b"\x01\x02" + b"\x00\x00\x00\x00\x00\x05" + struct.pack(
        "<II", 21, 42
    )


def _signature(marker: bytes, rodc_identifier: int | None = None) -> bytes:
    value = struct.pack("<i", 16) + marker * 12
    if rodc_identifier is not None:
        value += struct.pack("<H", rodc_identifier)
    return value


def _observation(*, rodc: bool = False) -> dict[str, object]:
    identifier = 7 if rodc else None
    pac = _pac(
        (17, struct.pack("<II", 2, 1)),
        (18, _sid()),
        (6, _signature(b"S")),
        (7, _signature(b"K", identifier)),
        (16, _signature(b"T", identifier)),
        (19, _signature(b"F", identifier)),
    )
    host = "ID-RODC01.idlab.test" if rodc else "ID-DC01.idlab.test"
    address = "172.28.30.11" if rodc else "172.28.30.10"
    role = "rodc" if rodc else "rwdc"
    ticket_kvno = 3
    kdc_key_version = (7 << 16) | 4 if rodc else 4
    return {
        "realm": "IDLAB.TEST",
        "principal": "pac-client@IDLAB.TEST",
        "service": "HTTP/pac-service.idlab.test",
        "started_utc": "2026-10-30T10:00:00Z",
        "ended_utc": "2026-10-30T10:00:02Z",
        "cache_before": [],
        "cache_after": ["HTTP/pac-service.idlab.test@IDLAB.TEST"],
        "requested_kdc": {"host": host, "address": address, "role": role},
        "observed_kdc": {"host": host, "address": address, "role": role},
        "ticket_kvno": ticket_kvno,
        "kdc_key_version": kdc_key_version,
        "frame_number": 61 if not rodc else 25,
        "capture_sha256": "a" * 64,
        "issued_by_rodc": rodc,
        "expected_rodc_identifier": identifier,
        "expected_requestor_sid": "S-1-5-21-42",
        "raw_pac_hex": pac.hex(),
    }


def _assert_no_raw_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("_", "")
            assert "rawpac" not in normalized
            assert "rawticket" not in normalized
            assert "signaturebytes" not in normalized
            _assert_no_raw_material(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_raw_material(item)


@pytest.mark.parametrize("rodc", [False, True])
def test_adapter_normalizes_bounded_pac_without_raw_material(rodc: bool) -> None:
    result = normalize_windows_pac_observation(_observation(rodc=rodc))

    assert result["realm"] == "IDLAB.TEST"
    assert result["principal"] == "pac-client@IDLAB.TEST"
    assert result["service"] == "HTTP/pac-service.idlab.test"
    assert result["cache_isolated"] is True
    assert result["kdc"]["matched_request"] is True
    assert result["pac"]["buffer_count"] == 6
    assert result["pac"]["buffer_types"] == [17, 18, 6, 7, 16, 19]
    assert result["pac"]["requestor_present"] is True
    assert result["pac"]["requestor_matches_principal"] is True
    assert result["pac"]["attributes_present"] is True
    assert [item["role"] for item in result["pac"]["signatures"]] == [
        "server",
        "kdc",
        "ticket",
        "extended_kdc",
    ]
    expected_identifier = 7 if rodc else None
    assert result["ticket"]["key_version"] == 3
    assert result["ticket"]["rodc_identifier"] is None
    assert result["kdc"]["key_version"] == 4
    assert result["kdc"]["rodc_identifier"] == expected_identifier
    assert result["packet"]["frame_number"] == (25 if rodc else 61)
    assert result["packet"]["capture_sha256"] == "a" * 64
    assert result["packet"]["pac_sha256"] == hashlib.sha256(
        bytes.fromhex(_observation(rodc=rodc)["raw_pac_hex"])
    ).hexdigest()
    assert result["pac"]["signatures"][1]["rodc_identifier"] == expected_identifier
    _assert_no_raw_material(result)


def test_adapter_rejects_kdc_mismatch_and_unbounded_identifiers() -> None:
    mismatch = _observation()
    mismatch["observed_kdc"] = {
        "host": "ID-RODC01.idlab.test",
        "address": "172.28.30.11",
        "role": "rodc",
    }
    with pytest.raises(ValueError, match="KDC observation does not match"):
        normalize_windows_pac_observation(mismatch)

    wrong_realm = _observation()
    wrong_realm["realm"] = "OTHER.TEST"
    with pytest.raises(ValueError, match="realm"):
        normalize_windows_pac_observation(wrong_realm)


def test_adapter_cli_writes_only_normalized_metadata(tmp_path: Path) -> None:
    source = tmp_path / "transient.json"
    destination = tmp_path / "normalized.json"
    source.write_text(json.dumps(_observation(rodc=True)), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "identity_invariants.adapters.windows_pac",
            str(source),
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")},
    )

    assert result.returncode == 0, result.stderr
    normalized = json.loads(destination.read_text(encoding="utf-8"))
    _assert_no_raw_material(normalized)
    assert normalized["kdc"]["rodc_identifier"] == 7


def test_live_windows_pac_evidence_is_normalized() -> None:
    configured = os.environ.get("WINDOWS_PAC_EVIDENCE")
    if configured is None:
        pytest.skip("WINDOWS_PAC_EVIDENCE is set only for the isolated Windows run")
    root = Path(configured)
    records = [
        json.loads(line)
        for line in (root / "evidence.jsonl").read_text(encoding="utf-8-sig").splitlines()
    ]
    assert records
    assert {record["kdc"]["role"] for record in records} == {"rwdc", "rodc"}
    for record in records:
        _assert_no_raw_material(record)
        assert record["realm"] == "IDLAB.TEST"
        assert record["principal"] == "pac-client@IDLAB.TEST"
        assert record["service"] == "HTTP/pac-service.idlab.test"
        assert record["cache_isolated"] is True
