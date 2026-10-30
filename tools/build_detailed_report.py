"""Build the public Program 1 monograph from reviewed repository evidence."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


EXPECTED_INVARIANTS = 37
EXPECTED_RECORDS = 25
EXPECTED_OUTCOMES = {
    "accept": 5,
    "reject": 1,
    "observe": 10,
    "skip": 6,
    "inconclusive": 3,
}
EXPECTED_LEDGER_SHA256 = (
    "9852c4e00a4c1b25165708541774ba23975ec6c97acd6e0c2b90c6377633f44c"
)
EXPECTED_TESTS = {
    "ubuntu": 148,
    "windows": 50,
    "total": 198,
    "conditional_integrations": 3,
}
OUTCOME_ORDER = ("accept", "reject", "observe", "skip", "inconclusive")
OUTCOME_LABELS = {
    "accept": "Kabul",
    "reject": "Ret",
    "observe": "Gözlem",
    "skip": "Atlandı",
    "inconclusive": "Sonuçsuz",
}
DOMAIN_LABELS = {
    "WIF": "Workload Identity Federation",
    "STS": "OAuth 2.0 Token Exchange",
    "OIDC": "OpenID Connect",
    "CKT": "Cloud Kerberos Trust",
    "PAC": "MS-PAC / MS-KILE",
    "DMSA": "Delegated Managed Service Account",
}

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_PLACEHOLDER = re.compile(r"\{\{[A-Z0-9_]+\}\}")
_PEM = re.compile(r"-----BEGIN [^-\r\n]*(?:PRIVATE KEY|OPENSSH)[^-\r\n]*-----")
_BEARER = re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}(?![A-Za-z0-9_-])"
)
_CREDENTIAL = re.compile(
    r"(?i)(?:password|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|raw[_-]?(?:ticket|assertion)|kerberos[_-]?ticket)"
    r"\s*[:=]"
)
_LOCAL_SECRET_PATH = re.compile(
    r"(?i)(?:[a-z]:\\[^\r\n<>]*\\secrets\\|\.credential\.xml)"
)


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one YAML mapping")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _domain(rule_id: str) -> str:
    prefix = rule_id.split("-", 1)[0]
    if prefix not in DOMAIN_LABELS:
        raise ValueError(f"unknown invariant domain: {rule_id}")
    return prefix


def _bounded_text(value: object, field: str, maximum: int = 2000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be a bounded non-empty string")
    if "\x00" in value:
        raise ValueError(f"{field} contains a NUL byte")
    return value


def _normalized_ledger(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        if not line:
            raise ValueError(f"empty evidence line: {line_number}")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"evidence line {line_number} is not an object")
        rule_id = value.get("rule_id")
        if not isinstance(rule_id, str):
            raise ValueError(f"evidence line {line_number} lacks rule_id")
        records.append(
            {
                "case_id": _bounded_text(value.get("case_id"), "case_id", 160),
                "evidence_class": _bounded_text(
                    value.get("evidence_class"), "evidence_class", 80
                ),
                "outcome": _bounded_text(value.get("outcome"), "outcome", 40),
                "reason": _bounded_text(value.get("reason"), "reason", 160),
                "rule_ids": [rule_id],
            }
        )
    return sorted(records, key=lambda item: (item["rule_ids"], item["case_id"]))


def _git_history(root: Path) -> list[dict[str, str]]:
    document = _json(root / "reports" / "program1-commit-history.json")
    if document.get("format_version") != 1:
        raise ValueError("commit history version is unsupported")
    raw_commits = document.get("commits")
    if not isinstance(raw_commits, list) or not raw_commits:
        raise ValueError("commit history is empty")
    commits: list[dict[str, str]] = []
    for index, value in enumerate(raw_commits, start=1):
        if not isinstance(value, dict):
            raise ValueError("commit history entry is not a mapping")
        sha = _bounded_text(value.get("sha"), "commit digest", 40)
        authored_at = _bounded_text(value.get("authored_at"), "commit date", 40)
        subject = _bounded_text(value.get("subject"), "commit subject", 200)
        if not _GIT_SHA.fullmatch(sha):
            raise ValueError("Git history contains an invalid commit digest")
        commits.append(
            {
                "index": str(index),
                "sha": sha,
                "short_sha": sha[:12],
                "authored_at": authored_at,
                "subject": subject,
            }
        )
    return commits


def _validate_source_bindings(
    sources_document: dict[str, Any], invariants: list[dict[str, Any]]
) -> list[dict[str, str]]:
    raw_sources = sources_document.get("sources")
    if not isinstance(raw_sources, dict) or not raw_sources:
        raise ValueError("source catalog is empty")
    sources: list[dict[str, str]] = []
    for source_id in sorted(raw_sources):
        descriptor = raw_sources[source_id]
        if not isinstance(descriptor, dict):
            raise ValueError(f"source {source_id} is not a mapping")
        url = _bounded_text(descriptor.get("primary_url"), "primary_url", 500)
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(f"source {source_id} is not HTTPS")
        sources.append(
            {
                "id": source_id,
                "title": _bounded_text(descriptor.get("title"), "title", 500),
                "revision": _bounded_text(
                    descriptor.get("revision"), "revision", 500
                ),
                "primary_url": url,
            }
        )
    known = {source["id"] for source in sources}
    for invariant in invariants:
        if invariant["source"] not in known:
            raise ValueError(f"invariant source is not declared: {invariant['id']}")
    return sources


def _validate_manifest_bindings(
    manifest: dict[str, Any], sources_manifest: dict[str, Any]
) -> None:
    if manifest.get("format_version") != 1:
        raise ValueError("evidence manifest version is unsupported")
    if manifest.get("ledger_sha256") != EXPECTED_LEDGER_SHA256:
        raise ValueError("evidence manifest digest is not the reviewed digest")
    if manifest.get("record_count") != EXPECTED_RECORDS:
        raise ValueError("evidence manifest record count is not reviewed")
    declared = manifest.get("source_manifests")
    source_descriptors = sources_manifest.get("sources")
    if not isinstance(declared, dict) or not isinstance(source_descriptors, dict):
        raise ValueError("source manifest binding is missing")
    normalized = {
        name: descriptor.get("sha256")
        for name, descriptor in source_descriptors.items()
        if isinstance(descriptor, dict)
    }
    if declared != normalized:
        raise ValueError("source manifest bindings disagree")
    if any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in declared.values()):
        raise ValueError("source manifest contains an invalid digest")


def _validate_test_results(document: dict[str, Any]) -> dict[str, int]:
    if document.get("format_version") != 1:
        raise ValueError("test verification version is unsupported")
    ubuntu = document.get("ubuntu")
    windows = document.get("windows")
    if not isinstance(ubuntu, dict) or not isinstance(windows, dict):
        raise ValueError("test verification platform records are missing")
    results = {
        "ubuntu": ubuntu.get("passed"),
        "windows": windows.get("passed"),
        "total": int(ubuntu.get("passed", -1)) + int(windows.get("passed", -1)),
        "conditional_integrations": document.get("conditional_integrations"),
    }
    if ubuntu.get("failed") != 0 or windows.get("failed") != 0:
        raise ValueError("test verification records a failing test")
    if results != EXPECTED_TESTS:
        raise ValueError("test verification totals are not the reviewed totals")
    return results


def build_report_model(root: Path) -> dict[str, Any]:
    """Load and cross-check every committed source used by the monograph."""

    root = root.resolve()
    catalog_document = _yaml(root / "spec" / "invariants.yaml")
    sources_document = _yaml(root / "spec" / "sources.yaml")
    report_document = _json(root / "reports" / "identity-invariants.json")
    manifest = _json(root / "evidence" / "manifest.json")
    source_manifest = _json(root / "evidence" / "sources.json")
    test_verification = _json(root / "reports" / "program1-test-verification.json")
    ledger_path = root / "evidence" / str(manifest.get("ledger"))

    _validate_manifest_bindings(manifest, source_manifest)
    if _sha256(ledger_path) != EXPECTED_LEDGER_SHA256:
        raise ValueError("ledger bytes do not match the reviewed digest")

    raw_invariants = catalog_document.get("invariants")
    if not isinstance(raw_invariants, list) or len(raw_invariants) != EXPECTED_INVARIANTS:
        raise ValueError("catalog does not contain the reviewed invariant count")
    catalog_by_id: dict[str, dict[str, Any]] = {}
    for value in raw_invariants:
        if not isinstance(value, dict):
            raise ValueError("catalog invariant is not a mapping")
        rule_id = _bounded_text(value.get("id"), "invariant id", 80)
        if rule_id in catalog_by_id:
            raise ValueError(f"duplicate invariant: {rule_id}")
        catalog_by_id[rule_id] = value

    report_invariants = report_document.get("invariants")
    if not isinstance(report_invariants, list) or len(report_invariants) != EXPECTED_INVARIANTS:
        raise ValueError("generated report invariant count is not reviewed")
    invariants: list[dict[str, Any]] = []
    for item in report_invariants:
        if not isinstance(item, dict):
            raise ValueError("generated invariant is not a mapping")
        rule_id = _bounded_text(item.get("id"), "invariant id", 80)
        source = catalog_by_id.get(rule_id)
        if source is None:
            raise ValueError(f"generated report contains unknown invariant: {rule_id}")
        for field in ("source", "section", "summary", "evidence_class"):
            if item.get(field) != source.get(field):
                raise ValueError(f"generated invariant field mismatch: {rule_id}/{field}")
        invariants.append(
            {
                **item,
                "domain": _domain(rule_id),
                "positive_cases": list(source.get("positive_cases", [])),
                "negative_cases": list(source.get("negative_cases", [])),
                "observe_cases": list(source.get("observe_cases", [])),
            }
        )
    invariants.sort(key=lambda item: item["id"])
    if set(catalog_by_id) != {item["id"] for item in invariants}:
        raise ValueError("catalog and generated report invariant sets disagree")

    sources = _validate_source_bindings(sources_document, invariants)
    ledger_records = _normalized_ledger(ledger_path)
    report_observations = report_document.get("observations")
    if not isinstance(report_observations, list):
        raise ValueError("generated report observations are missing")
    observations = sorted(
        report_observations,
        key=lambda item: (item.get("rule_ids"), item.get("case_id")),
    )
    if observations != ledger_records:
        raise ValueError("generated observations do not match ledger records")
    if len(observations) != EXPECTED_RECORDS:
        raise ValueError("observation count is not reviewed")
    outcomes = dict(Counter(item["outcome"] for item in observations))
    outcomes = {name: outcomes.get(name, 0) for name in OUTCOME_ORDER}
    if outcomes != EXPECTED_OUTCOMES:
        raise ValueError("outcome distribution is not reviewed")

    report_manifest = report_document.get("manifest")
    if report_manifest != {
        "ledger": manifest["ledger"],
        "ledger_sha256": manifest["ledger_sha256"],
        "record_count": manifest["record_count"],
    }:
        raise ValueError("generated report manifest does not match evidence manifest")
    artifact_hashes = report_document.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        raise ValueError("generated report artifact hashes are missing")
    if any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in artifact_hashes.values()):
        raise ValueError("generated report contains an invalid artifact digest")

    domain_counts = dict(Counter(item["domain"] for item in invariants))
    observation_domains = dict(
        Counter(_domain(item["rule_ids"][0]) for item in observations)
    )
    reason_counts = dict(Counter(item["reason"] for item in observations))
    evidence_classes = dict(Counter(item["evidence_class"] for item in observations))
    tests = _validate_test_results(test_verification)

    assessment = report_document.get("assessment")
    if assessment != {"cwe": "not assessed", "cvss": "not assessed"}:
        raise ValueError("generated report assessment boundary changed")

    return {
        "assessment": {
            "cwe": "not assessed",
            "cvss": "not assessed",
            "product_deviation": "not established",
        },
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "commits": _git_history(root),
        "domain_counts": dict(sorted(domain_counts.items())),
        "environment": dict(sorted(manifest["environment_fingerprint"].items())),
        "evidence_classes": dict(sorted(evidence_classes.items())),
        "invariants": invariants,
        "manifest": report_manifest,
        "observation_domains": dict(sorted(observation_domains.items())),
        "observations": observations,
        "outcomes": outcomes,
        "reason_counts": dict(sorted(reason_counts.items())),
        "source_manifests": dict(sorted(manifest["source_manifests"].items())),
        "sources": sources,
        "test_results": tests,
        "test_verification": test_verification,
    }


def validate_public_text(text: str) -> None:
    """Reject reusable credential, key, token, and local-secret-path shapes."""

    if not isinstance(text, str) or not text:
        raise ValueError("public text must be non-empty")
    if len(text.encode("utf-8")) > 8 * 1024 * 1024:
        raise ValueError("public text exceeds the 8 MiB bound")
    checks = (
        ("private-key-shaped", _PEM),
        ("bearer-shaped", _BEARER),
        ("token-shaped", _JWT),
        ("credential-shaped", _CREDENTIAL),
        ("local-secret-path-shaped", _LOCAL_SECRET_PATH),
    )
    for label, pattern in checks:
        if pattern.search(text):
            raise ValueError(f"public text contains {label} material")


def _h(value: object) -> str:
    return html.escape(str(value), quote=True)


def _outcomes_for_rule(
    observations: list[dict[str, Any]], rule_id: str
) -> str:
    values = [item for item in observations if rule_id in item["rule_ids"]]
    if not values:
        return '<span class="status unrecorded">Kayıt yok</span>'
    return " ".join(
        f'<span class="status {_h(item["outcome"])}">'
        f'{_h(OUTCOME_LABELS[item["outcome"]])}</span>'
        for item in values
    )


def _invariant_rows(model: dict[str, Any]) -> str:
    rows: list[str] = []
    for item in model["invariants"]:
        cases = (
            len(item["positive_cases"])
            + len(item["negative_cases"])
            + len(item["observe_cases"])
        )
        rows.append(
            "<tr>"
            f'<td class="mono keep">{_h(item["id"])}</td>'
            f'<td><span class="domain domain-{_h(item["domain"].lower())}">'
            f'{_h(item["domain"])}</span></td>'
            f'<td>{_h(item["summary"])}</td>'
            f'<td><a href="{_h(item["source_primary_url"])}">{_h(item["source"])}</a>'
            f'<br><small>{_h(item["section"])}</small></td>'
            f'<td class="mono">{_h(item["evidence_class"])}</td>'
            f'<td class="num">{cases}</td>'
            f'<td>{_outcomes_for_rule(model["observations"], item["id"])}</td>'
            "</tr>"
        )
    return "\n".join(rows)


def _observation_rows(model: dict[str, Any]) -> str:
    rows: list[str] = []
    for index, item in enumerate(model["observations"], start=1):
        rows.append(
            "<tr>"
            f'<td class="num">{index}</td>'
            f'<td class="mono">{_h(item["case_id"])}</td>'
            f'<td class="mono keep">{_h(", ".join(item["rule_ids"]))}</td>'
            f'<td><span class="status {_h(item["outcome"])}">'
            f'{_h(OUTCOME_LABELS[item["outcome"]])}</span></td>'
            f'<td class="mono">{_h(item["reason"])}</td>'
            f'<td class="mono">{_h(item["evidence_class"])}</td>'
            "</tr>"
        )
    return "\n".join(rows)


def _source_rows(model: dict[str, Any]) -> str:
    return "\n".join(
        "<tr>"
        f'<td class="mono keep">{_h(item["id"])}</td>'
        f'<td>{_h(item["title"])}</td>'
        f'<td>{_h(item["revision"])}</td>'
        f'<td class="url"><a href="{_h(item["primary_url"])}">{_h(item["primary_url"])}</a></td>'
        "</tr>"
        for item in model["sources"]
    )


def _hash_rows(model: dict[str, Any]) -> str:
    values = {
        "public-ledger": model["manifest"]["ledger_sha256"],
        **{
            f"source-manifest/{name}": digest
            for name, digest in model["source_manifests"].items()
        },
        **model["artifact_hashes"],
    }
    return "\n".join(
        "<tr>"
        f'<td class="mono">{_h(name)}</td>'
        f'<td class="mono hash">{_h(digest)}</td>'
        "</tr>"
        for name, digest in sorted(values.items())
    )


def _commit_rows(model: dict[str, Any]) -> str:
    return "\n".join(
        "<tr>"
        f'<td class="num">{_h(item["index"])}</td>'
        f'<td class="mono keep">{_h(item["short_sha"])}</td>'
        f'<td class="keep">{_h(item["authored_at"][:10])}</td>'
        f'<td>{_h(item["subject"])}</td>'
        "</tr>"
        for item in model["commits"]
    )


def _environment_rows(model: dict[str, Any]) -> str:
    return "\n".join(
        f"<tr><td class=\"mono\">{_h(name)}</td><td>{_h(value)}</td></tr>"
        for name, value in model["environment"].items()
    )


def _domain_rows(model: dict[str, Any]) -> str:
    return "\n".join(
        "<tr>"
        f'<td><span class="domain domain-{_h(name.lower())}">{_h(name)}</span></td>'
        f'<td>{_h(DOMAIN_LABELS[name])}</td>'
        f'<td class="num">{count}</td>'
        f'<td class="num">{model["observation_domains"].get(name, 0)}</td>'
        "</tr>"
        for name, count in model["domain_counts"].items()
    )


def _reason_rows(model: dict[str, Any]) -> str:
    return "\n".join(
        "<tr>"
        f'<td class="mono">{_h(reason)}</td>'
        f'<td class="num">{count}</td>'
        "</tr>"
        for reason, count in model["reason_counts"].items()
    )


def build_report(
    root: Path, template_path: Path, output_path: Path, data_output_path: Path
) -> None:
    """Validate sources and atomically emit HTML plus its audit data."""

    model = build_report_model(root)
    template = template_path.read_text(encoding="utf-8")
    fields = {
        "INVARIANT_ROWS": _invariant_rows(model),
        "OBSERVATION_ROWS": _observation_rows(model),
        "SOURCE_ROWS": _source_rows(model),
        "ARTIFACT_HASH_ROWS": _hash_rows(model),
        "COMMIT_ROWS": _commit_rows(model),
        "ENVIRONMENT_ROWS": _environment_rows(model),
        "DOMAIN_ROWS": _domain_rows(model),
        "REASON_ROWS": _reason_rows(model),
        "LEDGER_SHA256": model["manifest"]["ledger_sha256"],
        "COMMIT_COUNT": str(len(model["commits"])),
        "LAST_EVIDENCE_COMMIT": model["test_verification"]["evidence_commit"],
    }
    rendered = template
    for name, value in fields.items():
        placeholder = "{{" + name + "}}"
        if rendered.count(placeholder) < 1:
            raise ValueError(f"template requires at least one {name} placeholder")
        rendered = rendered.replace(placeholder, value)
    unresolved = _PLACEHOLDER.findall(rendered)
    if unresolved:
        raise ValueError(f"template contains unresolved placeholders: {unresolved}")
    if not rendered.endswith("\n"):
        rendered += "\n"
    validate_public_text(rendered)

    audit_model = {
        "assessment": model["assessment"],
        "artifact_hashes": model["artifact_hashes"],
        "commit_count": len(model["commits"]),
        "domain_counts": model["domain_counts"],
        "environment": model["environment"],
        "evidence_classes": model["evidence_classes"],
        "format_version": 1,
        "invariant_count": len(model["invariants"]),
        "ledger_sha256": model["manifest"]["ledger_sha256"],
        "observation_count": len(model["observations"]),
        "outcomes": model["outcomes"],
        "source_manifests": model["source_manifests"],
        "test_results": model["test_results"],
    }
    audit_text = json.dumps(
        audit_model, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True
    ) + "\n"
    validate_public_text(audit_text)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    data_output_path.parent.mkdir(parents=True, exist_ok=True)
    html_temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    data_temporary = data_output_path.with_suffix(data_output_path.suffix + ".tmp")
    html_temporary.write_text(rendered, encoding="utf-8", newline="\n")
    data_temporary.write_text(audit_text, encoding="utf-8", newline="\n")
    html_temporary.replace(output_path)
    data_temporary.replace(data_output_path)


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the reviewed Program 1 detailed HTML report."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument(
        "--template",
        type=Path,
        default=Path(__file__).parents[1]
        / "reports"
        / "program1-detailed-report.template.html",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parents[1]
        / "reports"
        / "program1-detailed-report.html",
    )
    parser.add_argument(
        "--data-output",
        type=Path,
        default=Path(__file__).parents[1]
        / "reports"
        / "program1-detailed-report-data.json",
    )
    arguments = parser.parse_args()
    build_report(
        arguments.root,
        arguments.template,
        arguments.output,
        arguments.data_output,
    )
    print(arguments.output)


if __name__ == "__main__":
    _main()
