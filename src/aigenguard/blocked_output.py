"""Concise terminal output for blocked policy enforcement."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .terminal import TerminalStyle


HTML_SUGGESTION = "run with --html to create agentbom.html"


def format_blocked_details(
    bom: dict[str, object],
    *,
    status: str,
    html_path: str | Path | None,
    html_suggestion: str = HTML_SUGGESTION,
    limit: int = 5,
    style: TerminalStyle | None = None,
) -> str:
    """Format a short blocked-output summary and local report pointer."""
    del limit
    style = TerminalStyle(enabled=False) if style is None else style
    summary = f"{status} {_blocked_sentence(bom)}"
    if _secret_values_contributed(bom):
        summary = f"{summary} Secret values were redacted."
    if html_path is None:
        detail = f"Detailed report: {style.dim(html_suggestion)}"
    else:
        detail = f"Detailed report: open {style.cyan(Path(html_path))}"
    return "\n".join([style.red(summary), detail])


def top_blocking_reasons(
    bom: dict[str, object],
    *,
    limit: int = 5,
) -> list[str]:
    """Return a metadata-free blocked summary for legacy callers."""
    del limit
    return [_blocked_sentence(bom)]


def _blocked_sentence(bom: dict[str, object]) -> str:
    count = _blocking_issue_count(bom)
    if count == 1:
        return "1 policy violation needs review."
    if count > 1:
        return f"{count} policy violations need review."
    return "Policy enforcement needs review."


def _blocking_issue_count(bom: dict[str, object]) -> int:
    policy_review = _dict(bom.get("policy_review"))
    violations = _finding_list(policy_review.get("violations"))
    if violations:
        return len(violations)
    return sum(
        len(_finding_list(bom.get(key)))
        for key in (
            "secret_leak_findings",
            "policy_findings",
            "reachable_capabilities",
            "mcp_servers",
        )
    )


def _secret_values_contributed(bom: dict[str, object]) -> bool:
    policy_review = _dict(bom.get("policy_review"))
    for item in _finding_list(policy_review.get("violations")):
        rule = str(item.get("rule", "")).lower()
        message = str(item.get("message", "")).lower()
        if rule.startswith("secrets.") or "secret" in message:
            return True
    return bool(_finding_list(bom.get("secret_leak_findings")))


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _finding_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
