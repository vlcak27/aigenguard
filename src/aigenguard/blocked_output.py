"""Concise terminal output for blocked policy enforcement."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TOP_REASON_LIMIT = 5
HTML_SUGGESTION = "run with --html to create agentbom.html"

_SECRET_VALUE_RE = re.compile(
    "|".join(
        [
            r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}",
            r"sk-ant-[A-Za-z0-9_-]{20,}",
            r"github_pat_[A-Za-z0-9_]{20,}",
            r"gh[pousr]_[A-Za-z0-9]{20,}",
            r"AIza[0-9A-Za-z_-]{20,}",
            r"hf_[A-Za-z0-9]{20,}",
        ]
    )
)


def format_blocked_details(
    bom: dict[str, object],
    *,
    html_path: str | Path | None,
    html_suggestion: str = HTML_SUGGESTION,
    limit: int = TOP_REASON_LIMIT,
) -> str:
    """Format a short blocked-output summary and local report pointer."""
    reasons = top_blocking_reasons(bom, limit=limit)
    lines = ["Top reasons:"]
    if reasons:
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append("- policy enforcement failed")
    lines.extend(["", "Detailed report:"])
    if html_path is None:
        lines.append(html_suggestion)
    else:
        lines.append(f"open {Path(html_path)}")
    return "\n".join(lines)


def top_blocking_reasons(
    bom: dict[str, object],
    *,
    limit: int = TOP_REASON_LIMIT,
) -> list[str]:
    """Return concise reason strings from existing report data only."""
    reasons: list[str] = []
    seen: set[str] = set()

    policy_review = _dict(bom.get("policy_review"))
    for item in _sorted_findings(_finding_list(policy_review.get("violations"))):
        _add_reason(reasons, seen, _policy_violation_reason(item, bom), limit)
        if len(reasons) >= limit:
            return reasons

    for item in _sorted_findings(_finding_list(bom.get("secret_leak_findings"))):
        if str(item.get("severity", "")).lower() != "critical":
            continue
        _add_reason(reasons, seen, _secret_leak_reason(item), limit)
        if len(reasons) >= limit:
            return reasons

    for item in _sorted_findings(_finding_list(bom.get("policy_findings"))):
        if not _high_or_critical(str(item.get("severity", ""))):
            continue
        _add_reason(reasons, seen, _policy_finding_reason(item, bom), limit)
        if len(reasons) >= limit:
            return reasons

    for item in _sorted_findings(_finding_list(bom.get("reachable_capabilities"))):
        if not _high_or_critical(str(item.get("risk", ""))):
            continue
        _add_reason(reasons, seen, _reachable_reason(item), limit)
        if len(reasons) >= limit:
            return reasons

    for item in _sorted_findings(_finding_list(bom.get("mcp_servers"))):
        if not _high_or_critical(str(item.get("risk", ""))):
            continue
        _add_reason(reasons, seen, _mcp_server_reason(item), limit)
        if len(reasons) >= limit:
            return reasons

    return reasons


def _policy_violation_reason(
    item: dict[str, Any],
    bom: dict[str, object],
) -> str:
    rule = str(item.get("rule", ""))
    message = str(item.get("message", ""))
    if rule.startswith("secrets.") and "value" in message.lower():
        return _secret_leak_reason(item)
    if rule == "capabilities.deny":
        capability = _capability_from_text(message) or "capability"
        match = _matching_reachable_capability(bom, item, capability)
        return _capability_reason(capability, match or item)
    if rule.startswith("mcp."):
        return _mcp_policy_reason(item, bom)
    if rule in {
        "providers.allow",
        "providers.deny",
        "models.allow",
        "models.deny",
        "frameworks.allow",
        "frameworks.deny",
    }:
        return _named_policy_reason(item, bom)
    if rule == "risk.warn_on":
        severity = str(item.get("severity", "high")).lower()
        return f"repository_risk: {severity}, policy threshold reached"
    return _generic_policy_reason(item)


def _named_policy_reason(item: dict[str, Any], bom: dict[str, object]) -> str:
    rule = str(item.get("rule", ""))
    section = rule.split(".", 1)[0]
    label = {"providers": "provider", "models": "model", "frameworks": "framework"}.get(
        section, section
    )
    name = _name_from_message(str(item.get("message", "")))
    match = _matching_named_item(bom, section, item, name)
    details = _detail_parts(match or item, default_severity=str(item.get("severity", "")))
    return f"{label} {name}: {', '.join(details)}" if name else _generic_policy_reason(item)


def _mcp_policy_reason(item: dict[str, Any], bom: dict[str, object]) -> str:
    name = _name_from_message(str(item.get("message", "")))
    reachable = _matching_mcp_reachable_capability(bom, item, name)
    if reachable:
        details = [f"reachable MCP {name or 'server'} exposure"]
        details.extend(_detail_parts(reachable, include_risk=False, include_location=False))
        return f"mcp_tool_invocation: {', '.join(details)}"

    server = _matching_mcp_server(bom, item, name)
    details = _detail_parts(server or item, default_severity=str(item.get("severity", "")))
    display = name or "server"
    return f"MCP {display}: {', '.join(details)}"


def _policy_finding_reason(
    item: dict[str, Any],
    bom: dict[str, object],
) -> str:
    message = str(item.get("message", ""))
    capability = _capability_from_text(message)
    if capability:
        match = _matching_capability_or_reachable(bom, item, capability)
        return _capability_reason(capability, match or item)
    if "mcp" in message.lower():
        return _mcp_policy_reason(item, bom)
    return _generic_policy_reason(item)


def _capability_reason(capability: str, item: dict[str, Any]) -> str:
    return f"{capability}: {', '.join(_detail_parts(item))}"


def _reachable_reason(item: dict[str, Any]) -> str:
    capability = str(item.get("capability", "capability"))
    if capability == "mcp_tool_invocation":
        server = str(item.get("mcp_server", "")).strip()
        details = [f"reachable MCP {server or 'server'} exposure"]
        details.extend(_detail_parts(item, include_risk=False, include_location=False))
        return f"mcp_tool_invocation: {', '.join(details)}"
    return _capability_reason(capability, item)


def _mcp_server_reason(item: dict[str, Any]) -> str:
    name = str(item.get("name", "server")).strip() or "server"
    return f"MCP {name}: {', '.join(_detail_parts(item))}"


def _secret_leak_reason(item: dict[str, Any]) -> str:
    severity = str(item.get("severity", "critical")).lower()
    details = [severity, "value redacted"]
    location = _location(item)
    if location:
        details.append(location)
    return f"secret_leak: {', '.join(details)}"


def _generic_policy_reason(item: dict[str, Any]) -> str:
    message = _compact(_redact_text(str(item.get("message", "policy violation"))))
    return f"policy_review: {', '.join(_detail_parts(item, prefix=message))}"


def _detail_parts(
    item: dict[str, Any],
    *,
    default_severity: str = "",
    prefix: str = "",
    include_risk: bool = True,
    include_location: bool = True,
) -> list[str]:
    details = [prefix] if prefix else []
    risk = str(item.get("risk") or "").lower()
    severity = str(item.get("severity") or default_severity).lower()
    confidence = str(item.get("confidence") or "").lower()
    policy_status = str(item.get("policy_status") or "").strip()

    if include_risk and risk:
        details.append(f"{risk} risk")
    elif severity:
        details.append(severity)
    if confidence:
        details.append(f"{confidence} confidence")
    if policy_status:
        details.append(f"policy status: {policy_status}")
    if include_location:
        location = _location(item)
        if location:
            details.append(location)
    return details or ["review required"]


def _matching_named_item(
    bom: dict[str, object],
    section: str,
    item: dict[str, Any],
    name: str,
) -> dict[str, Any] | None:
    source = _source(item)
    normalized_name = name.lower()
    for candidate in _finding_list(bom.get(section)):
        candidate_name = str(candidate.get("name", "")).lower()
        if normalized_name and candidate_name != normalized_name:
            continue
        if source and _source(candidate) != source:
            continue
        return _with_policy_status(candidate, item)
    return None


def _matching_capability_or_reachable(
    bom: dict[str, object],
    item: dict[str, Any],
    capability: str,
) -> dict[str, Any] | None:
    return _matching_reachable_capability(bom, item, capability) or _matching_capability(
        bom, item, capability
    )


def _matching_reachable_capability(
    bom: dict[str, object],
    item: dict[str, Any],
    capability: str,
) -> dict[str, Any] | None:
    source = _source(item)
    for candidate in _finding_list(bom.get("reachable_capabilities")):
        if str(candidate.get("capability", "")) != capability:
            continue
        if source and _source(candidate) != source:
            continue
        return _with_policy_status(candidate, item)
    return None


def _matching_capability(
    bom: dict[str, object],
    item: dict[str, Any],
    capability: str,
) -> dict[str, Any] | None:
    source = _source(item)
    aliases = {
        "shell_execution": "shell",
        "code_execution": "code_execution",
        "cloud_access": "cloud",
        "network_access": "network",
        "database_access": "database",
        "autonomous_execution": "autonomous_execution",
        "mcp_tool_invocation": "mcp_tool_invocation",
    }
    name = aliases.get(capability, capability)
    for candidate in _finding_list(bom.get("capabilities")):
        if str(candidate.get("name", "")) != name:
            continue
        if source and _source(candidate) != source:
            continue
        return _with_policy_status(candidate, item)
    return None


def _matching_mcp_reachable_capability(
    bom: dict[str, object],
    item: dict[str, Any],
    name: str,
) -> dict[str, Any] | None:
    source = _source(item)
    for candidate in _finding_list(bom.get("reachable_capabilities")):
        if str(candidate.get("capability", "")) != "mcp_tool_invocation":
            continue
        server = str(candidate.get("mcp_server", "")).lower()
        if name and server != name.lower():
            continue
        if source and _source(candidate) != source:
            continue
        return _with_policy_status(candidate, item)
    return None


def _matching_mcp_server(
    bom: dict[str, object],
    item: dict[str, Any],
    name: str,
) -> dict[str, Any] | None:
    source = _source(item)
    for candidate in _finding_list(bom.get("mcp_servers")):
        server = str(candidate.get("name", "")).lower()
        if name and server != name.lower():
            continue
        if source and _source(candidate) != source:
            continue
        return _with_policy_status(candidate, item)
    return None


def _with_policy_status(
    candidate: dict[str, Any],
    item: dict[str, Any],
) -> dict[str, Any]:
    return {
        **candidate,
        "policy_status": candidate.get("policy_status") or item.get("policy_status"),
    }


def _capability_from_text(text: str) -> str:
    lowered = text.lower().replace("-", "_")
    for capability in (
        "shell_execution",
        "code_execution",
        "mcp_tool_invocation",
        "network_access",
        "cloud_access",
        "database_access",
        "autonomous_execution",
    ):
        if capability in lowered:
            return capability
    if "shell execution" in lowered or "shell" in lowered:
        return "shell_execution"
    if "code execution" in lowered:
        return "code_execution"
    return ""


def _name_from_message(message: str) -> str:
    if ":" not in message:
        return ""
    return _redact_text(message.rsplit(":", 1)[-1].strip().strip(".").lower())


def _location(item: dict[str, Any]) -> str:
    source = _redact_text(_source(item))
    line = str(item.get("line", "")).strip()
    return f"{source}:{line}" if source and line else source


def _source(item: dict[str, Any]) -> str:
    for key in ("source", "source_file", "path"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _finding_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _sorted_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or item.get("risk") or "").lower(), 0),
            str(item.get("rule") or ""),
            _source(item),
            str(item.get("message") or item.get("name") or item.get("capability") or ""),
        ),
    )


def _high_or_critical(severity: str) -> bool:
    return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK["high"]


def _add_reason(
    reasons: list[str],
    seen: set[str],
    reason: str,
    limit: int,
) -> None:
    if len(reasons) >= limit:
        return
    if not reason or reason in seen:
        return
    seen.add(reason)
    reasons.append(reason)


def _compact(text: str, limit: int = 120) -> str:
    compacted = " ".join(text.split())
    if len(compacted) <= limit:
        return compacted
    return compacted[: limit - 3].rstrip() + "..."


def _redact_text(text: str) -> str:
    return _SECRET_VALUE_RE.sub("[REDACTED]", text)
