"""Normalize bounded Windows PAC observations without retaining ticket material."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from identity_invariants.canonical import JSONValue, digest_identifier, parse_json_object
from identity_invariants.pac.model import PacLimits, Sid
from identity_invariants.pac.parser import parse_pac, parse_signature


_REALM = "IDLAB.TEST"
_PRINCIPAL = "pac-client@IDLAB.TEST"
_SERVICE = "HTTP/pac-service.idlab.test"
_KDC_IDENTITIES = {
    "rwdc": ("ID-DC01.idlab.test", "172.28.30.10"),
    "rodc": ("ID-RODC01.idlab.test", "172.28.30.11"),
}
_SIGNATURE_ROLES = {
    6: "server",
    7: "kdc",
    16: "ticket",
    19: "extended_kdc",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _require_string(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _require_integer(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _require_boolean(document: Mapping[str, object], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _parse_utc(value: str, field: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError(f"{field} must use the UTC Z designator")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{field} must be UTC")
    return parsed


def _normalize_kdc(value: object, field: str) -> dict[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    role = value.get("role")
    host = value.get("host")
    address = value.get("address")
    if not isinstance(role, str) or role not in _KDC_IDENTITIES:
        raise ValueError(f"{field} role is not a bounded lab KDC")
    expected_host, expected_address = _KDC_IDENTITIES[role]
    if host != expected_host or address != expected_address:
        raise ValueError(f"{field} does not identify the expected {role}")
    return {"role": role, "host": expected_host, "address": expected_address}


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{field} must be a string array")
    result = list(value)
    if not all(isinstance(item, str) for item in result):
        raise ValueError(f"{field} must be a string array")
    return result


def _format_sid(value: Sid) -> str:
    suffix = "".join(f"-{part}" for part in value.subauthorities)
    return f"S-{value.revision}-{value.identifier_authority}{suffix}"


def _decode_pac(document: Mapping[str, object], limits: PacLimits) -> bytes:
    encoded = _require_string(document, "raw_pac_hex")
    if len(encoded) % 2:
        raise ValueError("raw_pac_hex must contain complete bytes")
    if len(encoded) > limits.max_total_size * 2:
        raise ValueError("raw_pac_hex exceeds the configured size")
    try:
        return bytes.fromhex(encoded)
    except ValueError as error:
        raise ValueError("raw_pac_hex must be hexadecimal") from error


def normalize_windows_pac_observation(
    document: Mapping[str, object],
) -> dict[str, JSONValue]:
    """Validate one lab observation and return metadata-only PAC evidence."""

    realm = _require_string(document, "realm")
    principal = _require_string(document, "principal")
    service = _require_string(document, "service")
    if realm != _REALM:
        raise ValueError(f"realm must be {_REALM}")
    if principal != _PRINCIPAL:
        raise ValueError(f"principal must be {_PRINCIPAL}")
    if service != _SERVICE:
        raise ValueError(f"service must be {_SERVICE}")

    started_text = _require_string(document, "started_utc")
    ended_text = _require_string(document, "ended_utc")
    started = _parse_utc(started_text, "started_utc")
    ended = _parse_utc(ended_text, "ended_utc")
    if ended < started:
        raise ValueError("ended_utc precedes started_utc")

    before = _string_list(document.get("cache_before"), "cache_before")
    after = _string_list(document.get("cache_after"), "cache_after")
    expected_cache_entry = f"{service}@{realm}"
    cache_isolated = expected_cache_entry not in before and after.count(
        expected_cache_entry
    ) == 1
    if not cache_isolated:
        raise ValueError("ticket cache is not isolated for the requested service")

    requested_kdc = _normalize_kdc(document.get("requested_kdc"), "requested_kdc")
    observed_kdc = _normalize_kdc(document.get("observed_kdc"), "observed_kdc")
    if requested_kdc != observed_kdc:
        raise ValueError("KDC observation does not match the requested KDC")

    issued_by_rodc = _require_boolean(document, "issued_by_rodc")
    expected_rodc = document.get("expected_rodc_identifier")
    if expected_rodc is not None and (
        isinstance(expected_rodc, bool)
        or not isinstance(expected_rodc, int)
        or not 0 < expected_rodc <= 0xFFFF
    ):
        raise ValueError("expected_rodc_identifier must be a 16-bit positive integer")
    if issued_by_rodc != (requested_kdc["role"] == "rodc"):
        raise ValueError("RODC issuance context does not match the requested KDC")
    if issued_by_rodc != (expected_rodc is not None):
        raise ValueError("RODC issuance context does not match its identifier")

    ticket_kvno = _require_integer(document, "ticket_kvno")
    if ticket_kvno <= 0 or ticket_kvno > 0xFFFF:
        raise ValueError("service ticket key version must be a non-zero 16-bit value")

    kdc_key_version = _require_integer(document, "kdc_key_version")
    if kdc_key_version <= 0 or kdc_key_version > 0xFFFFFFFF:
        raise ValueError("kdc_key_version is outside the unsigned 32-bit range")
    kdc_rodc = kdc_key_version >> 16 or None
    kdc_key_version_low = kdc_key_version & 0xFFFF
    if kdc_key_version_low == 0:
        raise ValueError("KDC key version must be non-zero")
    if kdc_rodc != expected_rodc:
        raise ValueError("KDC key version does not match the expected RODC")

    frame_number = _require_integer(document, "frame_number")
    if frame_number < 1:
        raise ValueError("frame_number must be positive")
    capture_sha256 = _require_string(document, "capture_sha256")
    if not _SHA256.fullmatch(capture_sha256):
        raise ValueError("capture_sha256 must be a lowercase SHA-256 digest")

    expected_sid = _require_string(document, "expected_requestor_sid")
    limits = PacLimits()
    pac_bytes = _decode_pac(document, limits)
    pac = parse_pac(pac_bytes, limits)
    requestor = _format_sid(pac.requestor_sid) if pac.requestor_sid else None

    signatures: list[JSONValue] = []
    for buffer in pac.buffers:
        role = _SIGNATURE_ROLES.get(buffer.type_id)
        if role is None:
            continue
        signature = parse_signature(
            buffer.data,
            issued_by_rodc=issued_by_rodc and buffer.type_id != 6,
        )
        if signature.rodc_identifier != (expected_rodc if buffer.type_id != 6 else None):
            raise ValueError(f"{role} signature RODC identifier does not match")
        signatures.append(
            {
                "role": role,
                "type": signature.signature_type,
                "digest": digest_identifier(
                    f"pac-signature:{role}", signature.signature.hex()
                ),
                "rodc_identifier": signature.rodc_identifier,
            }
        )

    if pac.attributes is None:
        attributes: JSONValue = None
    else:
        attributes = {
            "flags_length": pac.attributes.flags_length,
            "flags": pac.attributes.flags,
        }

    return {
        "realm": realm,
        "principal": principal,
        "service": service,
        "started_utc": started_text,
        "ended_utc": ended_text,
        "cache_isolated": cache_isolated,
        "kdc": {
            **requested_kdc,
            "matched_request": True,
            "key_version": kdc_key_version_low,
            "rodc_identifier": kdc_rodc,
        },
        "ticket": {
            "key_version": ticket_kvno,
            "rodc_identifier": None,
        },
        "packet": {
            "frame_number": frame_number,
            "capture_sha256": capture_sha256,
            "pac_sha256": hashlib.sha256(pac_bytes).hexdigest(),
        },
        "pac": {
            "buffer_count": len(pac.buffers),
            "buffer_types": [buffer.type_id for buffer in pac.buffers],
            "buffers": [
                {
                    "type": buffer.type_id,
                    "size": buffer.size,
                    "offset": buffer.offset,
                }
                for buffer in pac.buffers
            ],
            "attributes_present": pac.attributes is not None,
            "attributes": attributes,
            "requestor_present": requestor is not None,
            "requestor_matches_principal": requestor == expected_sid,
            "requestor_digest": (
                digest_identifier("pac-requestor-sid", requestor)
                if requestor is not None
                else None
            ),
            "signatures": signatures,
        },
    }


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize one transient Windows PAC observation."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    source = arguments.source.resolve()
    destination = arguments.destination.resolve()
    if source == destination:
        parser.error("source and destination must be different files")

    document = parse_json_object(source.read_text(encoding="utf-8-sig"))
    normalized = normalize_windows_pac_observation(document)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            normalized,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


if __name__ == "__main__":
    _main()
