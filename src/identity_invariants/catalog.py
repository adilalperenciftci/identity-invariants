"""Load and validate the machine-readable invariant catalog."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from identity_invariants.decisions import EvidenceClass, InvariantRule


def _load_mapping(path: Path) -> Mapping[str, Any]:
    try:
        if path.suffix == ".json":
            value = json.loads(path.read_text(encoding="utf-8"))
        else:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise ValueError(f"cannot load catalog input {path}: {error}") from error
    if not isinstance(value, Mapping):
        raise ValueError(f"catalog input {path} must contain a mapping")
    return value


def _format_schema_error(error: Any) -> str:
    location = ".".join(str(part) for part in error.absolute_path)
    return f"{location or '<root>'}: {error.message}"


def _load_sources(path: Path) -> Mapping[str, Mapping[str, str]]:
    document = _load_mapping(path)
    sources = document.get("sources")
    if not isinstance(sources, Mapping) or not sources:
        raise ValueError("sources must be a non-empty mapping")

    normalized: dict[str, Mapping[str, str]] = {}
    for source_id, raw_source in sources.items():
        if not isinstance(source_id, str) or not isinstance(raw_source, Mapping):
            raise ValueError("each source must use a string ID and mapping value")
        source: dict[str, str] = {}
        for field in ("title", "revision", "primary_url"):
            value = raw_source.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"source {source_id} requires non-empty {field}")
            source[field] = value
        parsed_url = urlparse(source["primary_url"])
        if parsed_url.scheme != "https" or not parsed_url.netloc:
            raise ValueError(f"source {source_id} primary_url must be an HTTPS URL")
        normalized[source_id] = source
    return normalized


def load_catalog(path: Path) -> tuple[InvariantRule, ...]:
    """Load one invariant catalog and attach immutable source provenance."""

    document = _load_mapping(path)
    schema = _load_mapping(path.parent / "schema" / "invariants.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        details = "; ".join(_format_schema_error(error) for error in errors)
        raise ValueError(f"invalid invariant catalog: {details}")

    sources = _load_sources(path.with_name("sources.yaml"))
    raw_rules = cast(list[Mapping[str, Any]], document["invariants"])
    seen_ids: set[str] = set()
    rules: list[InvariantRule] = []
    for raw_rule in raw_rules:
        rule_id = cast(str, raw_rule["id"])
        if rule_id in seen_ids:
            raise ValueError(f"duplicate invariant ID: {rule_id}")
        seen_ids.add(rule_id)

        negative_cases = tuple(cast(list[str], raw_rule["negative_cases"]))
        observe_cases = tuple(cast(list[str], raw_rule["observe_cases"]))
        if not negative_cases and not observe_cases:
            raise ValueError(
                f"invariant {rule_id} requires negative_cases or observe_cases"
            )

        source_id = cast(str, raw_rule["source"])
        if source_id not in sources:
            raise ValueError(f"invariant {rule_id} references unknown source {source_id}")
        source = sources[source_id]
        rules.append(
            InvariantRule(
                id=rule_id,
                source=source_id,
                source_title=source["title"],
                source_revision=source["revision"],
                source_primary_url=source["primary_url"],
                section=cast(str, raw_rule["section"]),
                summary=cast(str, raw_rule["summary"]),
                evidence_class=cast(EvidenceClass, raw_rule["evidence_class"]),
                positive_cases=tuple(cast(list[str], raw_rule["positive_cases"])),
                negative_cases=negative_cases,
                observe_cases=observe_cases,
            )
        )
    return tuple(rules)


def validate_catalog_coverage(
    rules: Collection[InvariantRule], required_ids: Collection[str]
) -> None:
    """Require exact coverage so renamed or omitted design rules fail closed."""

    actual_ids = {rule.id for rule in rules}
    expected_ids = set(required_ids)
    missing = sorted(expected_ids - actual_ids)
    unexpected = sorted(actual_ids - expected_ids)
    if missing or unexpected:
        parts: list[str] = []
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        if unexpected:
            parts.append(f"unexpected: {', '.join(unexpected)}")
        raise ValueError(f"catalog coverage mismatch ({'; '.join(parts)})")
