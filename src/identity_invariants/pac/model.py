"""Immutable PAC parser result types and limits."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PacLimits:
    max_buffers: int = 128
    max_total_size: int = 16 * 1024 * 1024
    max_buffer_size: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if min(self.max_buffers, self.max_total_size, self.max_buffer_size) < 1:
            raise ValueError("PAC limits must be positive")


@dataclass(frozen=True, slots=True)
class PacBuffer:
    type_id: int
    size: int
    offset: int
    data: memoryview


@dataclass(frozen=True, slots=True)
class PacAttributes:
    flags_length: int
    flags: int


@dataclass(frozen=True, slots=True)
class Sid:
    revision: int
    identifier_authority: int
    subauthorities: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PacSignature:
    signature_type: int
    signature: bytes
    rodc_identifier: int | None


@dataclass(frozen=True, slots=True)
class PacStructure:
    version: int
    buffers: tuple[PacBuffer, ...]
    attributes: PacAttributes | None
    requestor_sid: Sid | None
    ignored_duplicate_attributes: int
