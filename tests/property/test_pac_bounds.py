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


@settings(max_examples=100, derandomize=True)
@given(st.binary(min_size=0, max_size=128))
def test_arbitrary_bounded_input_never_escapes_declared_errors(data: bytes) -> None:
    try:
        parsed = parse_pac(data, PacLimits(max_buffers=8, max_total_size=128))
    except ValueError:
        return
    assert parsed.version == 0
    assert len(parsed.buffers) <= 8


def test_huge_declared_count_is_rejected_before_table_arithmetic() -> None:
    data = struct.pack("<II", 0xFFFFFFFF, 0)
    try:
        parse_pac(data, PacLimits(max_buffers=64))
    except ValueError as error:
        assert "buffer count" in str(error)
    else:
        raise AssertionError("huge PAC buffer count was accepted")
