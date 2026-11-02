from __future__ import annotations

import struct

from hypothesis import given, settings, strategies as st

from identity_invariants.pac.model import PacLimits
from identity_invariants.pac.parser import checked_region, parse_pac


@settings(max_examples=100, derandomize=True)
@given(
    offset=st.integers(min_value=-100, max_value=10_000),
    size=st.integers(min_value=-100, max_value=10_000),
    total=st.integers(min_value=0, max_value=10_000),
)
def test_checked_region_matches_bounded_arithmetic(
    offset: int, size: int, total: int
) -> None:
    valid = offset >= 0 and size >= 0 and offset <= total and size <= total - offset
    try:
        region = checked_region(offset, size, total)
    except ValueError:
        assert not valid
    else:
        assert valid
        assert region == slice(offset, offset + size)


@settings(max_examples=1000, derandomize=True)
@given(st.binary(min_size=0, max_size=2048))
def test_arbitrary_bounded_input_never_escapes_declared_errors(data: bytes) -> None:
    try:
        parsed = parse_pac(data, PacLimits(max_buffers=32, max_total_size=2048))
    except ValueError:
        return
    assert parsed.version == 0
    assert len(parsed.buffers) <= 32


_UNKNOWN_BUFFER_TYPES = tuple((*range(1, 17), *range(19, 65)))


@settings(max_examples=1000, derandomize=True, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.sampled_from(_UNKNOWN_BUFFER_TYPES),
            st.binary(min_size=1, max_size=64),
        ),
        min_size=1,
        max_size=16,
    )
)
def test_aligned_non_overlapping_unknown_buffers_round_trip(
    buffers: list[tuple[int, bytes]],
) -> None:
    table_size = 8 + 16 * len(buffers)
    cursor = (table_size + 7) & ~7
    data = bytearray(cursor)
    struct.pack_into("<II", data, 0, len(buffers), 0)
    expected: list[tuple[int, bytes]] = []
    for index, (type_id, payload) in enumerate(buffers):
        struct.pack_into("<IIQ", data, 8 + 16 * index, type_id, len(payload), cursor)
        data.extend(payload)
        expected.append((type_id, payload))
        cursor = (len(data) + 7) & ~7
        data.extend(b"\x00" * (cursor - len(data)))

    parsed = parse_pac(
        bytes(data),
        PacLimits(max_buffers=16, max_buffer_size=64, max_total_size=len(data)),
    )

    assert [(item.type_id, bytes(item.data)) for item in parsed.buffers] == expected


@settings(max_examples=500, derandomize=True)
@given(
    first=st.binary(min_size=1, max_size=64),
    second=st.binary(min_size=1, max_size=64),
)
def test_structured_overlapping_regions_are_always_rejected(
    first: bytes, second: bytes
) -> None:
    table_size = 8 + 2 * 16
    offset = (table_size + 7) & ~7
    total = offset + max(len(first), len(second))
    data = bytearray(total)
    struct.pack_into("<II", data, 0, 2, 0)
    struct.pack_into("<IIQ", data, 8, 1, len(first), offset)
    struct.pack_into("<IIQ", data, 24, 2, len(second), offset)
    data[offset : offset + len(first)] = first

    try:
        parse_pac(bytes(data), PacLimits(max_buffers=2, max_total_size=total))
    except ValueError as error:
        assert "overlap" in str(error)
    else:
        raise AssertionError("overlapping PAC regions were accepted")


def test_huge_declared_count_is_rejected_before_table_arithmetic() -> None:
    data = struct.pack("<II", 0xFFFFFFFF, 0)
    try:
        parse_pac(data, PacLimits(max_buffers=64))
    except ValueError as error:
        assert "buffer count" in str(error)
    else:
        raise AssertionError("huge PAC buffer count was accepted")
