"""Defensive parser for bounded PAC headers and selected buffer types."""

from __future__ import annotations

import struct

from identity_invariants.pac.model import (
    PacAttributes,
    PacBuffer,
    PacLimits,
    PacSignature,
    PacStructure,
    Sid,
)


PAC_ATTRIBUTES_INFO = 17
PAC_REQUESTOR_SID = 18
_HEADER_SIZE = 8
_INFO_BUFFER_SIZE = 16
_SIGNATURE_LENGTHS = {
    -138: 16,
    15: 12,
    16: 12,
    19: 16,
    20: 24,
}


def checked_region(offset: int, size: int, total: int) -> slice:
    """Return a checked region using subtraction before addition."""

    if offset < 0 or size < 0 or offset > total or size > total - offset:
        raise ValueError("region is outside the containing buffer")
    return slice(offset, offset + size)


def parse_attributes(buffer: memoryview) -> PacAttributes:
    """Parse PAC_ATTRIBUTES_INFO with 32-bit storage rounding."""

    if len(buffer) < 4:
        raise ValueError("PAC attributes buffer is shorter than FlagsLength")
    (flags_length,) = struct.unpack_from("<I", buffer, 0)
    words = (flags_length + 31) // 32
    storage_size = words * 4
    required = 4 + storage_size
    if len(buffer) != required:
        raise ValueError("PAC attributes storage length is invalid")
    raw_flags = int.from_bytes(buffer[4:required], "little")
    mask = (1 << flags_length) - 1 if flags_length else 0
    return PacAttributes(flags_length=flags_length, flags=raw_flags & mask)


def parse_requestor_sid(buffer: memoryview) -> Sid:
    """Parse one exact-length binary SID with bounded subauthorities."""

    if len(buffer) < 8:
        raise ValueError("requestor SID length is shorter than its header")
    revision = buffer[0]
    count = buffer[1]
    if revision != 1:
        raise ValueError("requestor SID revision must be 1")
    if count > 15:
        raise ValueError("requestor SID subauthority count exceeds 15")
    required = 8 + count * 4
    if len(buffer) != required:
        raise ValueError("requestor SID length does not match its count")
    identifier_authority = int.from_bytes(buffer[2:8], "big")
    subauthorities = tuple(
        struct.unpack_from("<I", buffer, 8 + index * 4)[0]
        for index in range(count)
    )
    return Sid(
        revision=revision,
        identifier_authority=identifier_authority,
        subauthorities=subauthorities,
    )


def parse_signature(buffer: memoryview, issued_by_rodc: bool) -> PacSignature:
    """Parse a signature using explicit RWDC/RODC issuance context."""

    if len(buffer) < 4:
        raise ValueError("PAC signature length is shorter than its type")
    (signature_type,) = struct.unpack_from("<i", buffer, 0)
    if signature_type not in _SIGNATURE_LENGTHS:
        raise ValueError("PAC signature type is not supported by this profile")
    signature_length = _SIGNATURE_LENGTHS[signature_type]
    required = 4 + signature_length + (2 if issued_by_rodc else 0)
    if len(buffer) != required:
        qualifier = "RODC " if issued_by_rodc else ""
        raise ValueError(f"PAC {qualifier}signature length is invalid")
    signature = bytes(buffer[4 : 4 + signature_length])
    rodc_identifier = (
        struct.unpack_from("<H", buffer, 4 + signature_length)[0]
        if issued_by_rodc
        else None
    )
    return PacSignature(
        signature_type=signature_type,
        signature=signature,
        rodc_identifier=rodc_identifier,
    )


def parse_pac(data: bytes, limits: PacLimits) -> PacStructure:
    """Parse a PACTYPE header and bounded immutable buffer views."""

    total = len(data)
    if total > limits.max_total_size:
        raise ValueError("PAC total size exceeds configured limit")
    if total < _HEADER_SIZE:
        raise ValueError("PAC table header is truncated")
    buffer_count, version = struct.unpack_from("<II", data, 0)
    if buffer_count > limits.max_buffers:
        raise ValueError("PAC buffer count exceeds configured limit")
    table_size = _HEADER_SIZE + buffer_count * _INFO_BUFFER_SIZE
    if table_size > total:
        raise ValueError("PAC table is truncated")
    if version != 0:
        raise ValueError("PAC version must be zero")

    view = memoryview(data)
    buffers: list[PacBuffer] = []
    regions: list[tuple[int, int]] = []
    for index in range(buffer_count):
        entry_offset = _HEADER_SIZE + index * _INFO_BUFFER_SIZE
        type_id, size, offset = struct.unpack_from("<IIQ", data, entry_offset)
        if size == 0:
            raise ValueError("PAC contains a zero-length buffer")
        if size > limits.max_buffer_size:
            raise ValueError("PAC buffer size exceeds configured limit")
        if offset % 8 != 0:
            raise ValueError("PAC buffer offset is not 8-byte aligned")
        if offset < table_size:
            raise ValueError("PAC buffer overlaps the header table")
        region = checked_region(offset, size, total)
        regions.append((region.start, region.stop))
        buffers.append(
            PacBuffer(
                type_id=type_id,
                size=size,
                offset=offset,
                data=view[region],
            )
        )

    ordered_regions = sorted(regions)
    for previous, current in zip(ordered_regions, ordered_regions[1:]):
        if current[0] < previous[1]:
            raise ValueError("PAC buffer regions overlap")

    attributes: PacAttributes | None = None
    requestor_sid: Sid | None = None
    ignored_duplicate_attributes = 0
    for buffer in buffers:
        if buffer.type_id == PAC_ATTRIBUTES_INFO:
            if attributes is None:
                attributes = parse_attributes(buffer.data)
            else:
                ignored_duplicate_attributes += 1
        elif buffer.type_id == PAC_REQUESTOR_SID:
            if requestor_sid is None:
                requestor_sid = parse_requestor_sid(buffer.data)

    return PacStructure(
        version=version,
        buffers=tuple(buffers),
        attributes=attributes,
        requestor_sid=requestor_sid,
        ignored_duplicate_attributes=ignored_duplicate_attributes,
    )
