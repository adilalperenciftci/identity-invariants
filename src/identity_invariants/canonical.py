"""Strict JSON parsing and privacy-preserving identifier helpers."""

from __future__ import annotations

import hashlib
import json
from typing import TypeAlias, cast


JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_json_object(text: str) -> dict[str, JSONValue]:
    """Parse a JSON object while rejecting duplicate members and NaN values."""

    value = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return cast(dict[str, JSONValue], value)


def digest_identifier(namespace: str, value: str) -> str:
    """Return a domain-separated digest without retaining the source value."""

    framed = f"{len(namespace)}:{namespace}{len(value)}:{value}".encode("utf-8")
    return hashlib.sha256(framed).hexdigest()
