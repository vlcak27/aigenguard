"""GitHub Actions job summary support."""

from __future__ import annotations

import html
import os
from pathlib import Path
from typing import Any, Mapping


MAX_SURFACE_ITEMS = 5
MAX_REACHABLE_CAPABILITIES = 10


def write_github_step_summary(
    bom: dict[str, Any],
    output_paths: list[Path],
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Append a concise scan summary to GitHub Actions job summary if enabled."""

    env = os.environ if environ is None else environ
    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return False

    try:
        with Path(summary_path).open("a", encoding="utf-8") as summary_file:
            summary_file.write(render_github_step_summary(bom, output_paths))
    except (OSError, ValueError):
        return False
    return True


def render_github_step_summary(bom: dict[str, Any], output_paths: list[Path]) -> str:
    risk = bom.get("repository_risk", {})
    if not isinstance(risk, dict):
        risk = {}
    severity = _markdown_text(risk.get("severity", "unknown"))
    score = _markdown_text(risk.get("score", "unknown"))

    lines = [
        "# AgentBOM scan summary",
        "",
        f"Risk: {severity} ({score}/100)",
        "",
        "## Detected AI surface",
        "",
        f"- Providers: {_joined_names(bom.get('providers', []))}",
        f"- Models: {_joined_names(bom.get('models', []))}",
        f"- Frameworks: {_joined_names(bom.get('frameworks', []))}",
        f"- MCP servers: {_mcp_summary(bom.get('mcp_servers', []))}",
        "",
    ]

    lines.extend(_policy_review_summary(bom.get("policy_review")))
    lines.extend(["## Reachable capabilities", ""])
    lines.extend(_reachable_capability_table(bom.get("reachable_capabilities", [])))
    lines.extend(["", "## Reports", ""])
    if output_paths:
        for path in output_paths:
            lines.append(f"- {_markdown_text(path.name)}")
    else:
        lines.append("None generated.")
    lines.append("")
    return "\n".join(lines)


def _policy_review_summary(policy_review: object) -> list[str]:
    if not isinstance(policy_review, dict):
        return []
    status = _policy_review_status(policy_review)
    violations = policy_review.get("violations", [])
    warnings = policy_review.get("warnings", [])
    violation_count = len(violations) if isinstance(violations, list) else 0
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    return [
        "## Policy review",
        "",
        f"Policy review: {_markdown_text(status)}",
        f"Mode: {_markdown_text(policy_review.get('mode', 'advisory'))}",
        f"Violations: {violation_count}",
        f"Warnings: {warning_count}",
        "",
    ]


def _policy_review_status(policy_review: dict[str, Any]) -> str:
    violations = policy_review.get("violations", [])
    warnings = policy_review.get("warnings", [])
    if isinstance(violations, list) and violations:
        return "failed"
    if isinstance(warnings, list) and warnings:
        return "passed with warnings"
    return "passed"


def _joined_names(items: object) -> str:
    names = _top_names(items)
    if not names:
        return "none"
    return ", ".join(_markdown_text(name) for name in names)


def _mcp_summary(items: object) -> str:
    if not isinstance(items, list):
        return "0"
    names = _top_names(items)
    if not names:
        return "0"
    return f"{len(items)} ({', '.join(_markdown_text(name) for name in names)})"


def _top_names(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    names = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return sorted(names)[:MAX_SURFACE_ITEMS]


def _reachable_capability_table(items: object) -> list[str]:
    if not isinstance(items, list) or not items:
        return ["None detected."]

    lines = [
        "| Capability | Reachable from | Risk | Source |",
        "| --- | --- | --- | --- |",
    ]
    rows = [
        item
        for item in items
        if isinstance(item, dict)
    ][:MAX_REACHABLE_CAPABILITIES]
    for item in rows:
        lines.append(
            "| {capability} | {reachable_from} | {risk} | {source_file} |".format(
                capability=_table_text(item.get("capability", "capability")),
                reachable_from=_table_text(item.get("reachable_from", "unknown")),
                risk=_table_text(item.get("risk", "unknown")),
                source_file=_table_text(item.get("source_file", "unknown")),
            )
        )
    if len(items) > MAX_REACHABLE_CAPABILITIES:
        lines.append(
            "| {capability} | {reachable_from} | {risk} | {source_file} |".format(
                capability=_table_text("additional findings omitted"),
                reachable_from="",
                risk="",
                source_file="",
            )
        )
    return lines


def _table_text(value: object) -> str:
    return _markdown_text(value).replace("|", "\\|")


def _markdown_text(value: object) -> str:
    text = " ".join(str(value).splitlines())
    escaped = html.escape(text, quote=False)
    for char in "\\`*_{}[]()#+!":
        escaped = escaped.replace(char, f"\\{char}")
    return escaped
