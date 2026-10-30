"""Render verified evidence into deterministic Markdown and JSON reports."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from identity_invariants.catalog import load_catalog
from identity_invariants.decisions import InvariantRule
from identity_invariants.evidence.ledger import verify_manifest


_OUTCOMES = {"accept", "reject", "observe", "skip", "inconclusive"}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9-]{2,79}$")
_REASON = re.compile(r"^[a-z][a-z0-9._-]{0,159}$")
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_EVIDENCE_CLASSES = {
    "spec-oracle",
    "local-adapter",
    "windows-observation",
    "entra-observation",
}
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}"
    r"(?![A-Za-z0-9_-])"
)
_UUID = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
    r"(?![0-9a-f])"
)
_PEM = re.compile(r"-----BEGIN [^-\r\n]*(?:PRIVATE KEY|OPENSSH)[^-\r\n]*-----")
_BEARER = re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+")
_SECRET_FIELD = re.compile(
    r"(?i)[\"'`]?"
    r"(?:password|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|raw[_-]?(?:ticket|assertion)|kerberos[_-]?ticket)"
    r"[\"'`]?\s*[:=]"
)
_CREDENTIAL_PATH = re.compile(
    r"(?i)(?:[a-z]:\\[^\r\n]*\\secrets\\|\.credential\.xml)"
)
_MAX_REPORT_BYTES = 4 * 1024 * 1024
_TEMPLATE_FIELDS = (
    "TITLE",
    "ASSESSMENT",
    "EVIDENCE",
    "ENVIRONMENT",
    "MATRIX",
    "OBSERVATIONS",
    "LIMITATIONS",
    "ARTIFACT_HASHES",
)
_DEFAULT_TEMPLATE = (
    Path(__file__).resolve().parents[3] / "reports" / "template.md"
)


def _scalar(value: object) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, str):
        return value
    raise ValueError("report record fields must be strings")


def _mapping(record: object) -> dict[str, Any]:
    if is_dataclass(record) and not isinstance(record, type):
        return cast(dict[str, Any], asdict(record))
    if isinstance(record, Mapping):
        return dict(record)
    raise ValueError("evidence records must be mappings or dataclasses")


def _rule_ids(record: Mapping[str, Any]) -> tuple[str, ...]:
    if "rule_id" in record:
        rule_id = _scalar(record["rule_id"])
        if not _RULE_ID.fullmatch(rule_id):
            raise ValueError("evidence record contains an invalid invariant ID")
        return (rule_id,)
    values = record.get("rule_ids", record.get("invariant_ids"))
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError("evidence record requires rule_id or invariant_ids")
    rule_ids = tuple(_scalar(value) for value in values)
    if any(not _RULE_ID.fullmatch(rule_id) for rule_id in rule_ids):
        raise ValueError("evidence record contains an invalid invariant ID")
    if len(set(rule_ids)) != len(rule_ids):
        raise ValueError("evidence record contains duplicate invariant IDs")
    return rule_ids


def _markdown(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def _normalized_records(records: Sequence[object]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in records:
        record = _mapping(item)
        case_id = _scalar(record.get("case_id"))
        if not _CASE_ID.fullmatch(case_id):
            raise ValueError("evidence case_id is outside the report bound")
        outcome = _scalar(record.get("outcome"))
        if outcome not in _OUTCOMES:
            raise ValueError(f"unsupported evidence outcome: {outcome}")
        reason = _scalar(record.get("reason"))
        if not _REASON.fullmatch(reason):
            raise ValueError("evidence reason is outside the report bound")
        evidence_class = _scalar(record.get("evidence_class"))
        if evidence_class not in _EVIDENCE_CLASSES:
            raise ValueError("evidence class is not recognized")
        rule_ids = _rule_ids(record)
        digests = record.get("artifact_digests", {})
        if not isinstance(digests, Mapping):
            raise ValueError("artifact_digests must be a mapping")
        normalized_digests: dict[str, str] = {}
        for name, digest in digests.items():
            if not isinstance(name, str) or not _ARTIFACT_NAME.fullmatch(name):
                raise ValueError("artifact digest names must be bounded strings")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise ValueError("artifact values must be lowercase SHA-256 digests")
            normalized_digests[name] = digest
        normalized.append(
            {
                "case_id": case_id,
                "rule_ids": rule_ids,
                "outcome": outcome,
                "reason": reason,
                "evidence_class": evidence_class,
                "artifact_digests": normalized_digests,
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["rule_ids"],
            item["case_id"],
            item["outcome"],
            item["reason"],
        ),
    )


def _catalog_index(
    catalog: Sequence[InvariantRule],
) -> tuple[tuple[InvariantRule, ...], dict[str, InvariantRule]]:
    ordered = tuple(sorted(catalog, key=lambda rule: rule.id))
    index = {rule.id: rule for rule in ordered}
    if len(index) != len(ordered):
        raise ValueError("catalog contains duplicate invariant IDs")
    for rule in ordered:
        if not _RULE_ID.fullmatch(rule.id):
            raise ValueError(f"catalog contains invalid invariant ID: {rule.id}")
        source_url = urlparse(rule.source_primary_url)
        if (
            source_url.scheme != "https"
            or not source_url.netloc
            or any(character.isspace() for character in rule.source_primary_url)
        ):
            raise ValueError(f"catalog source must be an HTTPS URL: {rule.id}")
    return ordered, index


def render_invariant_matrix(
    catalog: Sequence[InvariantRule], records: Sequence[object]
) -> str:
    """Render every catalog rule with stable source and evidence mapping."""

    ordered_rules, index = _catalog_index(catalog)
    normalized = _normalized_records(records)
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in normalized:
        for rule_id in record["rule_ids"]:
            if rule_id not in index:
                raise ValueError(f"evidence references unknown invariant: {rule_id}")
            by_rule[rule_id].append(record)

    lines = [
        "| Invariant | Primary source | Section | Evidence class | Outcomes | Cases |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for rule in ordered_rules:
        mapped = by_rule.get(rule.id, [])
        outcomes = "<br>".join(
            sorted(
                {
                    f"`{record['outcome']}` ({_markdown(record['reason'])})"
                    for record in mapped
                }
            )
        )
        if not outcomes:
            outcomes = "`not recorded`"
        source = (
            f"[{_markdown(rule.source_title)}]({rule.source_primary_url}) "
            f"({_markdown(rule.source_revision)})"
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{rule.id}`",
                    source,
                    _markdown(rule.section),
                    f"`{rule.evidence_class}`",
                    outcomes,
                    str(len(mapped)),
                )
            )
            + " |"
        )
    return "\n".join(lines)


def _load_manifest(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    verify_manifest(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("evidence manifest must be a JSON object")
    format_version = document.get("format_version")
    if type(format_version) is not int or format_version != 1:
        raise ValueError("evidence manifest format version is not supported")
    record_count = document.get("record_count")
    if type(record_count) is not int or record_count < 0:
        raise ValueError("evidence manifest record count is invalid")
    ledger_name = document.get("ledger")
    if not isinstance(ledger_name, str):
        raise ValueError("evidence manifest requires a ledger")
    ledger_path = path.parent / ledger_name
    raw_records: list[object] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        _validate_report_content(line, len(line.encode("utf-8")))
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("evidence ledger lines must be JSON objects")
        raw_records.append(value)
    return document, _normalized_records(raw_records)


def _bounded_string_mapping(value: object, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not _ARTIFACT_NAME.fullmatch(key)
            or not isinstance(item, str)
            or not item
            or len(item) > 500
        ):
            raise ValueError(f"{field} entries must be bounded strings")
        result[key] = item
    return dict(sorted(result.items()))


def _source_manifests(value: object) -> dict[str, str]:
    sources = _bounded_string_mapping(value, "source_manifests")
    for digest in sources.values():
        if not _DIGEST.fullmatch(digest):
            raise ValueError("source manifest values must be SHA-256 digests")
    return sources


def _environment_markdown(environment: Mapping[str, str]) -> str:
    if not environment:
        return "No environment fingerprint was supplied."
    lines = ["| Component | Fingerprint |", "| --- | --- |"]
    for key, value in environment.items():
        lines.append(f"| {_markdown(key)} | {_markdown(value)} |")
    return "\n".join(lines)


def _observations_markdown(records: Sequence[Mapping[str, Any]]) -> str:
    if not records:
        return "No evidence records were supplied."
    lines: list[str] = []
    for record in records:
        rules = ", ".join(f"`{rule_id}`" for rule_id in record["rule_ids"])
        lines.extend(
            (
                f"### `{_markdown(record['case_id'])}`",
                "",
                f"- Invariant: {rules}",
                f"- Outcome: `{record['outcome']}`",
                f"- Reason: `{_markdown(record['reason'])}`",
                f"- Evidence class: `{_markdown(record['evidence_class'])}`",
                "",
            )
        )
    return "\n".join(lines).rstrip()


def _artifact_hashes(
    records: Sequence[Mapping[str, Any]], source_manifests: Mapping[str, str]
) -> dict[str, str]:
    hashes = {
        f"source-manifest/{name}": digest
        for name, digest in source_manifests.items()
    }
    for record in records:
        for name, digest in record["artifact_digests"].items():
            key = f"record/{record['case_id']}/{name}"
            previous = hashes.get(key)
            if previous is not None and previous != digest:
                raise ValueError(f"conflicting artifact digest: {key}")
            hashes[key] = digest
    return dict(sorted(hashes.items()))


def _hashes_markdown(hashes: Mapping[str, str]) -> str:
    if not hashes:
        return "No supporting artifact hashes were supplied."
    return "\n".join(f"- `{name}`: `{digest}`" for name, digest in hashes.items())


def _template() -> str:
    template = _DEFAULT_TEMPLATE.read_text(encoding="utf-8")
    for field in _TEMPLATE_FIELDS:
        if template.count("{{" + field + "}}") != 1:
            raise ValueError(f"report template requires one {field} placeholder")
    return template


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def validate_report_safety(path: Path) -> None:
    """Reject reusable credential, token, key, and raw identifier shapes."""

    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("unsafe report content: report is not UTF-8") from error
    _validate_report_content(text, len(data))


def _validate_report_content(text: str, byte_count: int | None = None) -> None:
    if byte_count is None:
        byte_count = len(text.encode("utf-8"))
    if byte_count > _MAX_REPORT_BYTES:
        raise ValueError("unsafe report content: report exceeds size bound")
    if "\x00" in text:
        raise ValueError("unsafe report content: NUL byte")
    checks = (
        ("private key", _PEM),
        ("bearer header", _BEARER),
        ("credential field", _SECRET_FIELD),
        ("token-shaped value", _JWT),
        ("local credential path", _CREDENTIAL_PATH),
        ("unredacted identifier", _UUID),
    )
    for description, pattern in checks:
        if pattern.search(text):
            raise ValueError(f"unsafe report content: {description}")


def render_technical_report(
    manifest: Path,
    catalog: Sequence[InvariantRule],
    output: Path,
) -> Path:
    """Verify evidence and render deterministic Markdown plus JSON."""

    manifest_document, records = _load_manifest(manifest)
    ordered_rules, index = _catalog_index(catalog)
    for record in records:
        for rule_id in record["rule_ids"]:
            if rule_id not in index:
                raise ValueError(f"evidence references unknown invariant: {rule_id}")
    environment = _bounded_string_mapping(
        manifest_document.get("environment_fingerprint"),
        "environment_fingerprint",
    )
    sources = _source_manifests(manifest_document.get("source_manifests"))
    hashes = _artifact_hashes(records, sources)
    matrix = render_invariant_matrix(ordered_rules, records)
    limitations = (
        "- Local oracle results are not statements about hosted service behavior.\n"
        "- Live Entra and Cloud Kerberos behavior remains unassessed when its "
        "prerequisite gate reports `skip`.\n"
        "- PAC requestor binding remains inconclusive where only the service "
        "ticket, not the encrypted TGT, was decoded.\n"
        "- CWE and CVSS remain `not assessed` until product behavior and impact "
        "are independently confirmed."
    )
    assessment = "- CWE: `not assessed`\n- CVSS: `not assessed`"
    evidence = (
        f"- Ledger: `{manifest_document['ledger']}`\n"
        f"- Ledger SHA-256: `{manifest_document['ledger_sha256']}`\n"
        f"- Record count: `{manifest_document['record_count']}`"
    )
    fields = {
        "TITLE": "Microsoft Identity Protocol Invariant Evidence",
        "ASSESSMENT": assessment,
        "EVIDENCE": evidence,
        "ENVIRONMENT": _environment_markdown(environment),
        "MATRIX": matrix,
        "OBSERVATIONS": _observations_markdown(records),
        "LIMITATIONS": limitations,
        "ARTIFACT_HASHES": _hashes_markdown(hashes),
    }
    markdown = _template()
    for name, value in fields.items():
        markdown = markdown.replace("{{" + name + "}}", value)
    if re.search(r"\{\{[A-Z_]+\}\}", markdown):
        raise ValueError("report template contains unresolved placeholders")
    if not markdown.endswith("\n"):
        markdown += "\n"

    observations = [
        {
            "case_id": record["case_id"],
            "evidence_class": record["evidence_class"],
            "outcome": record["outcome"],
            "reason": record["reason"],
            "rule_ids": list(record["rule_ids"]),
        }
        for record in records
    ]
    model = {
        "assessment": {"cwe": "not assessed", "cvss": "not assessed"},
        "artifact_hashes": hashes,
        "environment_fingerprint": environment,
        "format_version": 1,
        "invariant_count": len(ordered_rules),
        "invariants": [
            {
                "evidence_class": rule.evidence_class,
                "id": rule.id,
                "section": rule.section,
                "source": rule.source,
                "source_primary_url": rule.source_primary_url,
                "source_revision": rule.source_revision,
                "source_title": rule.source_title,
                "summary": rule.summary,
            }
            for rule in ordered_rules
        ],
        "manifest": {
            "ledger": manifest_document["ledger"],
            "ledger_sha256": manifest_document["ledger_sha256"],
            "record_count": manifest_document["record_count"],
        },
        "observations": observations,
        "record_count": len(records),
        "source_manifests": sources,
    }
    sidecar = json.dumps(
        model,
        ensure_ascii=True,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"

    _validate_report_content(markdown)
    _validate_report_content(sidecar)
    _write_atomic(output, markdown)
    sidecar_path = output.with_suffix(".json")
    _write_atomic(sidecar_path, sidecar)
    return output


def _main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Verify or render evidence reports.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-only", type=Path, metavar="MANIFEST")
    mode.add_argument("--render", type=Path, metavar="MANIFEST")
    parser.add_argument("--catalog", type=Path, default=Path("spec/invariants.yaml"))
    parser.add_argument("--output", type=Path, default=Path("reports/report.md"))
    arguments = parser.parse_args(argv)
    if arguments.verify_only is not None:
        document, records = _load_manifest(arguments.verify_only)
        print(
            "verified "
            f"{arguments.verify_only}: {len(records)} records, "
            f"ledger {document['ledger_sha256']}"
        )
        return
    catalog = load_catalog(arguments.catalog)
    rendered = render_technical_report(arguments.render, catalog, arguments.output)
    print(rendered)


if __name__ == "__main__":
    _main()
