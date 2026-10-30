from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from identity_invariants.pac.model import PacLimits
from identity_invariants.pac.parser import (
    checked_region,
    parse_attributes,
    parse_pac,
    parse_requestor_sid,
    parse_signature,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "pac"


def _pac(*buffers: tuple[int, bytes, int | None]) -> bytes:
    header_size = 8 + 16 * len(buffers)
    next_offset = (header_size + 7) & ~7
    entries: list[bytes] = []
    payload = bytearray(next_offset)
    struct.pack_into("<II", payload, 0, len(buffers), 0)
    for index, (type_id, value, explicit_offset) in enumerate(buffers):
        offset = next_offset if explicit_offset is None else explicit_offset
        entries.append(struct.pack("<IIQ", type_id, len(value), offset))
        required = offset + len(value)
        if required > len(payload):
            payload.extend(b"\x00" * (required - len(payload)))
        payload[offset:required] = value
        if explicit_offset is None:
            next_offset = (required + 7) & ~7
            if next_offset > len(payload):
                payload.extend(b"\x00" * (next_offset - len(payload)))
    for index, entry in enumerate(entries):
        start = 8 + index * 16
        payload[start : start + 16] = entry
    return bytes(payload)


def test_minimal_fixture_is_stable_and_preserves_unknown_buffer() -> None:
    data = (FIXTURES / "minimal-unknown.bin").read_bytes()
    assert hashlib.sha256(data).hexdigest() == (
        "6e584278f6c148ab2ad4c92630c0bbb9a67e1d2b54cc4da7a69c3f82f466b4b2"
    )

    parsed = parse_pac(data, PacLimits())

    assert parsed.version == 0
    assert len(parsed.buffers) == 1
    assert parsed.buffers[0].type_id == 99
    assert bytes(parsed.buffers[0].data) == b"PACFIX01"


def test_checked_region_rejects_negative_overflow_and_out_of_bounds() -> None:
    assert checked_region(8, 4, 12) == slice(8, 12)
    for offset, size, total in [(-1, 1, 8), (0, -1, 8), (9, 0, 8), (7, 2, 8)]:
        with pytest.raises(ValueError, match="region"):
            checked_region(offset, size, total)


def test_parser_rejects_truncated_table_and_limit_excess() -> None:
    with pytest.raises(ValueError, match="table"):
        parse_pac(struct.pack("<II", 2, 0), PacLimits())
    with pytest.raises(ValueError, match="buffer count"):
        parse_pac(struct.pack("<II", 2, 0) + b"\x00" * 32, PacLimits(max_buffers=1))


def test_parser_rejects_misaligned_out_of_bounds_and_overlapping_buffers() -> None:
    with pytest.raises(ValueError, match="aligned"):
        parse_pac(_pac((1, b"12345678", 25)), PacLimits())

    out_of_bounds = bytearray(_pac((1, b"12345678", None)))
    struct.pack_into("<Q", out_of_bounds, 16, 1_000)
    with pytest.raises(ValueError, match="region"):
        parse_pac(bytes(out_of_bounds), PacLimits())

    with pytest.raises(ValueError, match="overlap"):
        parse_pac(
            _pac((1, b"A" * 16, 40), (2, b"B" * 8, 48)), PacLimits()
        )


def test_parser_rejects_zero_length_and_oversized_buffers() -> None:
    with pytest.raises(ValueError, match="zero-length"):
        parse_pac(_pac((1, b"", None)), PacLimits())
    with pytest.raises(ValueError, match="buffer size"):
        parse_pac(_pac((1, b"12345678", None)), PacLimits(max_buffer_size=4))


def test_duplicate_attributes_keep_first_and_record_ignored_count() -> None:
    first = struct.pack("<II", 2, 1)
    second = struct.pack("<II", 2, 2)
    parsed = parse_pac(_pac((17, first, None), (17, second, None)), PacLimits())

    assert parsed.attributes is not None
    assert parsed.attributes.flags == 1
    assert parsed.ignored_duplicate_attributes == 1


def test_attribute_flags_use_32_bit_rounding_and_ignore_padding_bits() -> None:
    attributes = parse_attributes(memoryview(struct.pack("<II", 2, 0xFFFFFFFF)))
    assert attributes.flags_length == 2
    assert attributes.flags == 0b11

    extended = parse_attributes(
        memoryview(struct.pack("<III", 33, 0xFFFFFFFF, 0xFFFFFFFF))
    )
    assert extended.flags == (1 << 33) - 1
    with pytest.raises(ValueError, match="storage"):
        parse_attributes(memoryview(struct.pack("<II", 33, 0)))


def test_requestor_sid_enforces_revision_count_and_exact_length() -> None:
    sid_bytes = b"\x01\x02" + b"\x00\x00\x00\x00\x00\x05" + struct.pack(
        "<II", 21, 42
    )
    sid = parse_requestor_sid(memoryview(sid_bytes))
    assert sid.revision == 1
    assert sid.identifier_authority == 5
    assert sid.subauthorities == (21, 42)

    with pytest.raises(ValueError, match="revision"):
        parse_requestor_sid(memoryview(b"\x02" + sid_bytes[1:]))
    with pytest.raises(ValueError, match="length"):
        parse_requestor_sid(memoryview(sid_bytes[:-1]))


def test_signature_length_and_rodc_identifier_are_context_bound() -> None:
    signature = struct.pack("<i", 16) + b"S" * 12
    parsed = parse_signature(memoryview(signature), issued_by_rodc=False)
    assert parsed.signature_type == 16
    assert parsed.rodc_identifier is None

    rodc = parse_signature(
        memoryview(signature + struct.pack("<H", 7)), issued_by_rodc=True
    )
    assert rodc.rodc_identifier == 7
    with pytest.raises(ValueError, match="RODC"):
        parse_signature(memoryview(signature), issued_by_rodc=True)
    with pytest.raises(ValueError, match="length"):
        parse_signature(memoryview(signature + b"\x07\x00"), issued_by_rodc=False)
