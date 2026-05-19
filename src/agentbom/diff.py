"""Diff support for AgentBOM reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


DIFF_CATEGORIES = (
    "providers",
    "capabilities",
    "mcp_servers",
    "secret_references",
    "secret_leak_findings",
    "policy_findings",
)
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CAPABILITY_SEVERITIES = {
    "shell": "high",
    "code_execution": "high",
    "autonomous_execution": "high",
    "network": "medium",
    "database": "medium",
    "cloud": "medium",
    "mcp_tool_invocation": "medium",
}


def load_baseline_report(path: str | Path) -> dict[str, Any]:
    baseline_path = Path(path)
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline report does not exist: {baseline_path}")
    if not baseline_path.is_file():
        raise FileNotFoundError(f"baseline report is not a file: {baseline_path}")
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid baseline JSON at line {exc.lineno}, column {exc.colno}: {baseline_path}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"baseline report must be a JSON object: {baseline_path}")
    return data


def attach_diff(bom: dict[str, Any], baseline: dict[str, Any]) -> None:
    bom["diff"] = diff_reports(baseline, bom)


def diff_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_findings = _findings_by_id(baseline)
    current_findings = _findings_by_id(current)

    baseline_ids = set(baseline_findings)
    current_ids = set(current_findings)

    return {
        "baseline_repository": str(baseline.get("repository", "")),
        "current_repository": str(current.get("repository", "")),
        "introduced": _sorted_findings(
            current_findings[item_id] for item_id in current_ids - baseline_ids
        ),
        "resolved": _sorted_findings(
            baseline_findings[item_id] for item_id in baseline_ids - current_ids
        ),
        "unchanged": _sorted_findings(
            current_findings[item_id] for item_id in current_ids & baseline_ids
        ),
    }


def has_new_findings_at_or_above(diff: dict[str, Any], severity: str) -> bool:
    threshold = SEVERITY_ORDER[severity]
    return any(
        SEVERITY_ORDER.get(str(item.get("severity", "low")), 1) >= threshold
        for item in _list(diff.get("introduced"))
    )


def valid_severities() -> tuple[str, ...]:
    return tuple(SEVERITY_ORDER)


def _findings_by_id(report: dict[str, Any]) -> dict[str, dict[str, str]]:
    findings: dict[str, dict[str, str]] = {}
    for category in DIFF_CATEGORIES:
        for item in _list(report.get(category)):
            if not isinstance(item, dict):
                continue
            finding = _diff_finding(category, item)
            findings[finding["id"]] = finding
    return findings


def _diff_finding(category: str, item: dict[str, Any]) -> dict[str, str]:
    identity = _identity(category, item)
    title = _title(category, item)
    source_file = _source_file(category, item)
    severity = _severity(category, item)
    finding_id = _finding_id(category, identity)
    finding = {
        "id": finding_id,
        "category": category,
        "title": title,
        "source_file": source_file,
        "severity": severity,
    }
    if category == "policy_findings":
        message = str(item.get("message", ""))
        if message:
            finding["message"] = message
    return finding


def _identity(category: str, item: dict[str, Any]) -> dict[str, str]:
    if category == "policy_findings":
        return {
            "category": category,
            "message": str(item.get("message", "")),
            "source_file": str(item.get("source_file", "")),
            "policy_id": str(item.get("policy_id", "")),
        }
    if category == "secret_leak_findings":
        return {
            "category": category,
            "provider": str(item.get("provider", "")),
            "category_name": str(item.get("category", "")),
            "path": str(item.get("path", "")),
            "line": str(item.get("line", "")),
            "redacted_evidence": str(item.get("redacted_evidence", "")),
        }
    return {
        "category": category,
        "name": str(item.get("name", "")),
        "path": str(item.get("path", "")),
    }


def _finding_id(category: str, identity: dict[str, str]) -> str:
    material = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    label = identity.get("name") or identity.get("message") or category
    return f"{category}.{_slug(label)}.{digest}"


def _title(category: str, item: dict[str, Any]) -> str:
    if category == "policy_findings":
        return str(item.get("message", "policy finding"))
    if category == "secret_leak_findings":
        return str(item.get("title", "Possible secret value"))
    return str(item.get("name", item.get("path", category)))


def _source_file(category: str, item: dict[str, Any]) -> str:
    if category == "policy_findings":
        return str(item.get("source_file", ""))
    if category == "secret_leak_findings":
        return str(item.get("path", ""))
    return str(item.get("path", ""))


def _severity(category: str, item: dict[str, Any]) -> str:
    if category == "policy_findings":
        return _known_severity(str(item.get("severity", "low")))
    if category == "capabilities":
        return CAPABILITY_SEVERITIES.get(str(item.get("name", "")), "low")
    if category == "mcp_servers":
        return _known_severity(str(item.get("risk", "low")))
    if category == "secret_references":
        return "high"
    if category == "secret_leak_findings":
        return _known_severity(str(item.get("severity", "critical")))
    return "low"


def _known_severity(severity: str) -> str:
    return severity if severity in SEVERITY_ORDER else "low"


def _sorted_findings(items: Any) -> list[dict[str, str]]:
    return sorted(
        (item for item in items if isinstance(item, dict)),
        key=lambda item: (
            str(item.get("category", "")),
            str(item.get("severity", "")),
            str(item.get("source_file", "")),
            str(item.get("title", "")),
            str(item.get("id", "")),
        ),
    )


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    return slug or "finding"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
