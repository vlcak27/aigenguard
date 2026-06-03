"""HTML report writer for AigenGuard."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path
from typing import Any

from .policy_onboarding import starter_policy_toml


class SafeHtml(str):
    """Explicit marker for report-owned HTML fragments."""


SECTION_HELP = {
    "providers-models": (
        "AI providers and concrete model identifiers found in source or configuration."
    ),
    "frameworks": (
        "Agent frameworks that may route prompts, memory, tools, callbacks, "
        "or autonomous loops."
    ),
    "mcp": (
        "MCP inventory from local JSON configuration. Reachable exposure is reported "
        "separately when static agent, framework, or prompt evidence supports it."
    ),
    "reachable": (
        "Inferred actor-to-capability paths where static evidence suggests an AI "
        "component may be able to use a sensitive action or configured MCP server. "
        "AigenGuard does not execute MCP servers or prove runtime reachability."
    ),
    "policy": (
        "Missing controls or custom policy violations that should be resolved "
        "or accepted explicitly."
    ),
    "policy-review": "Result of evaluating the supplied AigenGuard TOML policy.",
    "policy-workbench": (
        "Generate a starter aigenguard.toml from current findings, then choose a local "
        "guard mode."
    ),
    "prompts": "Prompt and instruction files that may influence agent behavior.",
    "dependencies": "AI, MCP, and sandbox dependencies detected in supported package manifests.",
    "secrets": "Credential names referenced by the repository. Values are never stored or printed.",
    "secret-leaks": (
        "Likely AI/API credential values found by deterministic static checks. "
        "Values are always redacted."
    ),
    "graph": (
        "The same capability relationships represented as nodes and edges for "
        "architectural review."
    ),
    "diff": "Changes since the supplied baseline report.",
}


def write_html_report(bom: dict[str, Any], output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "agentbom.html"
    html_path.write_text(render_html(bom), encoding="utf-8")
    return html_path


def render_html(bom: dict[str, Any]) -> str:
    risk = _dict(bom.get("repository_risk"))
    score = _int(risk.get("score"), 0)
    severity = str(risk.get("severity", "low"))
    graph = _dict(bom.get("capability_graph"))

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>AigenGuard Security Report</title>",
            f"<style>{_css()}</style>",
            "</head>",
            "<body>",
            '<div class="layout">',
            _sidebar(bom),
            '<main class="content">',
            _overview(bom, risk, score, severity),
            _review_workflow(bom),
            _diff_summary(bom.get("diff", {})),
            _policy_review(bom.get("policy_review")),
            _review_priorities(bom),
            _providers_and_models(bom),
            _named_section("Frameworks", "frameworks", bom.get("frameworks", [])),
            _mcp_security(bom.get("mcp_servers", [])),
            _reachable_capabilities(bom.get("reachable_capabilities", [])),
            _policy_findings(bom.get("policy_findings", [])),
            _prompt_surfaces(bom.get("prompts", [])),
            _dependencies(bom.get("dependencies", [])),
            _named_section("Secret References", "secrets", bom.get("secret_references", [])),
            _secret_leaks(bom.get("secret_leak_findings", [])),
            _policy_workbench(bom),
            _capability_graph(graph),
            "</main>",
            "</div>",
            _policy_workbench_script(bom),
            "</body>",
            "</html>",
            "",
        ]
    )


def _sidebar(bom: dict[str, Any]) -> str:
    sections = [
        ("Overview", "overview"),
        ("Review Workflow", "review-workflow"),
        ("Review Priorities", "priorities"),
        ("Providers & Models", "providers-models"),
        ("Frameworks", "frameworks"),
        ("MCP Security Analysis", "mcp"),
        ("Reachable Capabilities", "reachable"),
        ("Policy Findings", "policy"),
        ("Prompt Files", "prompts"),
        ("Dependencies", "dependencies"),
        ("Secret References", "secrets"),
        ("Secret Leak Findings", "secret-leaks"),
        ("Policy Workbench", "policy-workbench"),
        ("Capability Graph", "graph"),
    ]
    if _dict(bom.get("diff")):
        sections.insert(1, ("Changes", "diff"))
    if _dict(bom.get("policy_review")):
        sections.insert(2 if _dict(bom.get("diff")) else 1, ("Policy Review", "policy-review"))
    links = "\n".join(
        f'<a href="#{section_id}">{escape(label)}</a>' for label, section_id in sections
    )
    return (
        '<aside class="sidebar">'
        '<div class="brand">AigenGuard</div>'
        '<div class="subtitle">Offline AI agent review</div>'
        f'<nav aria-label="Report sections">{links}</nav>'
        "</aside>"
    )


def _overview(
    bom: dict[str, Any], risk: dict[str, Any], score: int, severity: str
) -> str:
    rationale = _list(risk.get("rationale"))
    guidance = _risk_guidance(severity)
    schema = escape(str(bom.get("schema_version", "")))
    generated_by = escape(str(bom.get("generated_by", "")))
    counts = [
        ("Providers", len(_list(bom.get("providers")))),
        ("Models", len(_list(bom.get("models")))),
        ("Frameworks", len(_list(bom.get("frameworks")))),
        ("MCP", len(_list(bom.get("mcp_servers")))),
        ("Reachable", len(_list(bom.get("reachable_capabilities")))),
        ("Policy", len(_list(bom.get("policy_findings")))),
    ]
    cards = "\n".join(
        (
            '<div class="metric">'
            f'<span class="metric-value">{value}</span>'
            f'<span class="metric-label">{escape(label)}</span>'
            "</div>"
        )
        for label, value in counts
    )
    rationale_html = _bullets(rationale, "No repository-level risk factors detected.")
    risks = _scanner_risks(bom.get("risks", []))
    return (
        '<section id="overview" class="section">'
        '<div class="section-heading">'
        "<h1>Overview</h1>"
        f'<span class="badge {_badge_class(severity)}">{escape(severity)}</span>'
        "</div>"
        '<p class="section-lede">'
        "AigenGuard maps AI-specific components, reachable capabilities, and policy gaps "
        "using deterministic offline static analysis."
        "</p>"
        '<div class="overview-grid">'
        '<div class="score-panel">'
        f'<div class="score-ring {_severity_class(severity)}" style="--score: {score}">'
        f'<span>{score}</span>'
        "</div>"
        '<div class="score-copy">'
        "<h2>Repository Risk</h2>"
        f"<p>{escape(str(bom.get('repository', 'unknown repository')))}</p>"
        "</div>"
        "</div>"
        f'<div class="metrics">{cards}</div>'
        "</div>"
        '<div class="meta-grid">'
        f"<div><span>Schema</span><strong>{schema}</strong></div>"
        f"<div><span>Generated by</span><strong>{generated_by}</strong></div>"
        "</div>"
        '<div class="explanation">'
        "<h2>How to read this report</h2>"
        "<p>"
        "Start with review priorities, reachable capabilities, and policy findings. "
        "Then use the component sections to confirm which files introduced each signal."
        "</p>"
        f"<p>{escape(guidance)}</p>"
        "</div>"
        "<h2>Risk Rationale</h2>"
        f"{rationale_html}"
        f"{risks}"
        "</section>"
    )


def _risk_guidance(severity: str) -> str:
    if severity == "critical":
        return "Critical means at least one AI-connected path deserves review before deployment."
    if severity == "high":
        return "High means the repository contains sensitive capabilities or policy gaps to triage."
    if severity == "medium":
        return "Medium means there are review signals, but they may be expected for this agent."
    return "Low means AigenGuard did not find strong repository-level risk signals."


def _policy_review(policy_review_value: Any) -> str:
    policy_review = _dict(policy_review_value)
    if not policy_review:
        return ""
    status = _policy_review_status(policy_review)
    mode = str(policy_review.get("mode", "advisory"))
    policy_file = str(policy_review.get("policy_file", ""))
    violations = _policy_review_items(policy_review.get("violations"))
    warnings = _policy_review_items(policy_review.get("warnings"))
    note = ""
    if mode == "advisory":
        note = (
            '<p class="subtle">'
            "Advisory mode does not fail CI. Use --enforce-policy to make violations fail."
            "</p>"
        )
    return (
        '<section id="policy-review" class="section">'
        '<div class="section-heading">'
        "<h1>Policy Review</h1>"
        f'<span class="badge status-{_class_token(status)}">{escape(status)}</span>'
        "</div>"
        f'<p class="section-lede">{escape(SECTION_HELP["policy-review"])}</p>'
        '<div class="meta-grid">'
        f"<div><span>Status</span><strong>{escape(status)}</strong></div>"
        f"<div><span>Mode</span><strong>{escape(mode)}</strong></div>"
        f"<div><span>Policy file</span><strong>{escape(policy_file)}</strong></div>"
        f"<div><span>Violations</span><strong>{len(violations)}</strong></div>"
        "</div>"
        f"{note}"
        "<h2>Violations</h2>"
        f"{_policy_review_table(violations)}"
        "<h2>Warnings</h2>"
        f"{_policy_review_table(warnings)}"
        "</section>"
    )


def _policy_review_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _policy_review_table(items: list[dict[str, Any]]) -> str:
    rows = [
        [
            _badge(str(item.get("severity", ""))),
            str(item.get("rule", "")),
            str(item.get("message", "")),
            str(item.get("source", "")),
            str(item.get("suggested_remediation", "")),
            _policy_status_badge(item.get("policy_status")),
        ]
        for item in items
    ]
    return _table(
        ["Severity", "Rule", "Message", "Source", "Remediation", "Policy Status"],
        rows,
        "None.",
    )


def _policy_review_status(policy_review: dict[str, Any]) -> str:
    violations = _policy_review_items(policy_review.get("violations"))
    warnings = _policy_review_items(policy_review.get("warnings"))
    if violations:
        return "failed"
    if warnings:
        return "passed with warnings"
    return "passed"


def _review_workflow(bom: dict[str, Any]) -> str:
    policy_review = _dict(bom.get("policy_review"))
    title = "Review workflow"
    if not policy_review:
        body = [
            "Review reachable capabilities and policy findings.",
            "Use Policy Workbench to generate a starter aigenguard.toml.",
        ]
        command = "aigenguard scan . --policy aigenguard.toml --html --open"
    else:
        status = _policy_review_status(policy_review)
        mode = str(policy_review.get("mode", "advisory"))
        if mode == "enforced":
            if status == "failed":
                body = [
                    "Policy enforcement failed.",
                    "Fix policy violations before relying on enforcement.",
                ]
            else:
                body = [f"Policy enforcement {status}.", "Review warnings before release."]
            command = ""
        else:
            body = [
                f"Policy review {status}.",
                "Review violations and warnings, then update aigenguard.toml if needed.",
                "Enforce only after advisory results match expectations.",
            ]
            command = "aigenguard scan . --policy aigenguard.toml --enforce-policy"
    body_html = "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in body) + "</ul>"
    command_html = f"<pre><code>{escape(command)}</code></pre>" if command else ""
    return (
        '<section id="review-workflow" class="section">'
        f"<h1>{escape(title)}</h1>"
        '<div class="workflow-card">'
        f"{body_html}"
        f"{command_html}"
        "</div>"
        "</section>"
    )


def _review_priorities(bom: dict[str, Any]) -> str:
    priorities = _priority_items(bom)
    if priorities:
        body = "<ol>" + "".join(f"<li>{escape(item)}</li>" for item in priorities) + "</ol>"
    else:
        body = '<p class="empty">No immediate review priorities detected.</p>'
    return (
        '<section id="priorities" class="section">'
        "<h1>Review Priorities</h1>"
        '<p class="section-lede">'
        "A short queue for reviewers who need to decide what matters first."
        "</p>"
        f"{body}"
        "</section>"
    )


def _priority_items(bom: dict[str, Any]) -> list[str]:
    priorities: list[str] = []
    for item in _list(bom.get("reachable_capabilities")):
        finding = _dict(item)
        if finding.get("risk") == "high":
            priorities.append(
                "Review reachable {capability} from {reachable_from} in {source_file}.".format(
                    capability=finding.get("capability", "capability"),
                    reachable_from=finding.get("reachable_from", "agent actor"),
                    source_file=finding.get("source_file", "unknown file"),
                )
            )
    for item in _list(bom.get("policy_findings")):
        finding = _dict(item)
        if finding.get("severity") in {"critical", "high", "medium"}:
            priorities.append(
                "Address policy finding in {source_file}: {message}.".format(
                    source_file=finding.get("source_file", "unknown file"),
                    message=finding.get("message", "policy control needed"),
                )
            )
    if _list(bom.get("secret_references")):
        priorities.append("Confirm referenced credentials are stored outside the repository.")
    if _list(bom.get("secret_leak_findings")):
        priorities.append("Remove leaked credential values from the repository and rotate them.")
    return priorities[:5]


def _diff_summary(diff_value: Any) -> str:
    diff = _dict(diff_value)
    if not diff:
        return ""
    parts = []
    counts = [
        ("Introduced", len(_list(diff.get("introduced")))),
        ("Resolved", len(_list(diff.get("resolved")))),
        ("Unchanged", len(_list(diff.get("unchanged")))),
    ]
    count_cards = "".join(
        (
            '<div class="metric diff-metric">'
            f'<span class="metric-value">{value}</span>'
            f'<span class="metric-label">{escape(label)}</span>'
            "</div>"
        )
        for label, value in counts
    )
    for key, title in (
        ("introduced", "Introduced Findings"),
        ("resolved", "Resolved Findings"),
        ("unchanged", "Unchanged Findings"),
    ):
        rows = [
            [
                str(_dict(item).get("id", "")),
                str(_dict(item).get("category", "")),
                str(_dict(item).get("title", "")),
                str(_dict(item).get("source_file", "")),
                _badge(str(_dict(item).get("severity", ""))),
            ]
            for item in _list(diff.get(key))
        ]
        parts.append(
            f"<h2>{escape(title)}</h2>"
            f"{_table(['ID', 'Category', 'Finding', 'Source File', 'Severity'], rows, 'None.')}"
        )
    return (
        '<section id="diff" class="section">'
        "<h1>Changes since baseline</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["diff"])}</p>'
        f'<div class="metrics diff-counts">{count_cards}</div>'
        f"{''.join(parts)}"
        "</section>"
    )


def _scanner_risks(items: Any) -> str:
    risks = _list(items)
    if not risks:
        return ""
    rows = [
        [
            _badge(str(_dict(item).get("severity", ""))),
            str(_dict(item).get("reason", "")),
        ]
        for item in risks
    ]
    return (
        "<h2>Scanner Risks</h2>"
        '<p class="subtle">Scanner risks summarize review signals. They are not exploit claims.</p>'
        + _table(["Severity", "Reason"], rows, "None detected.")
    )


def _providers_and_models(bom: dict[str, Any]) -> str:
    providers = _named_rows(bom.get("providers", []))
    models = [
        [
            str(_dict(item).get("name", "")),
            str(_dict(item).get("type", "")),
            str(_dict(item).get("source_file", "")),
            _badge(str(_dict(item).get("confidence", "")), "confidence"),
            str(_dict(item).get("evidence", "")),
        ]
        for item in _list(bom.get("models"))
    ]
    return (
        '<section id="providers-models" class="section">'
        "<h1>Providers &amp; Models</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["providers-models"])}</p>'
        "<h2>Providers</h2>"
        f"{_table(['Provider', 'Path', 'Confidence'], providers, 'None detected.')}"
        "<h2>Models</h2>"
        f"{_table(_model_headers(), models, 'None detected.')}"
        "</section>"
    )


def _named_section(title: str, section_id: str, items: Any) -> str:
    rows = _named_rows(items)
    intro = SECTION_HELP.get(section_id)
    intro_html = f'<p class="section-lede">{escape(intro)}</p>' if intro else ""
    return (
        f'<section id="{section_id}" class="section">'
        f"<h1>{escape(title)}</h1>"
        f"{intro_html}"
        f"{_table(['Name', 'Path', 'Confidence'], rows, 'None detected.')}"
        "</section>"
    )


def _named_rows(items: Any) -> list[list[str]]:
    return [
        [
            str(_dict(item).get("name", _dict(item).get("path", ""))),
            str(_dict(item).get("path", "")),
            _badge(str(_dict(item).get("confidence", "")), "confidence"),
        ]
        for item in _list(items)
    ]


def _mcp_security(items: Any) -> str:
    rows = []
    for item in _list(items):
        finding = _dict(item)
        rows.append(
            [
                str(finding.get("name", "")),
                str(finding.get("path", "")),
                str(finding.get("command", "")),
                " ".join(str(value) for value in _list(finding.get("args"))),
                str(finding.get("package", "")),
                str(finding.get("transport", "")),
                ", ".join(str(value) for value in _list(finding.get("env"))),
                _badge(str(finding.get("risk", ""))),
                ", ".join(str(value) for value in _list(finding.get("risk_categories"))),
                "; ".join(str(value) for value in _list(finding.get("rationale"))),
                _policy_status_badge(finding.get("policy_status")),
            ]
        )
    return (
        '<section id="mcp" class="section">'
        "<h1>MCP Security Analysis</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["mcp"])}</p>'
        f"{_table(_mcp_headers(), rows, 'None detected.')}"
        "</section>"
    )


def _reachable_capabilities(items: Any) -> str:
    rows = []
    for item in _list(items):
        finding = _dict(item)
        paths = finding.get("paths", [])
        if not isinstance(paths, list):
            paths = []
        rows.append(
            [
                str(finding.get("capability", "")),
                str(finding.get("reachable_from", "")),
                str(finding.get("source_file", "")),
                _badge(str(finding.get("risk", ""))),
                _badge(str(finding.get("confidence", "")), "confidence"),
                str(finding.get("confidence_score", "")),
                ", ".join(str(path) for path in paths),
                str(finding.get("mcp_server", "")),
                ", ".join(str(value) for value in _list(finding.get("mitigations"))),
                "; ".join(str(value) for value in _list(finding.get("rationale"))),
                _policy_status_badge(finding.get("policy_status")),
            ]
        )
    return (
        '<section id="reachable" class="section">'
        "<h1>Reachable Capabilities</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["reachable"])}</p>'
        f"{_table(_reachable_headers(), rows, 'None detected.')}"
        "</section>"
    )


def _policy_findings(items: Any) -> str:
    rows = [
        [
            _badge(str(_dict(item).get("severity", ""))),
            str(_dict(item).get("message", "")),
            str(_dict(item).get("source_file", "")),
            str(_dict(item).get("policy_id", "")),
            _policy_status_badge(_dict(item).get("policy_status")),
        ]
        for item in _list(items)
    ]
    return (
        '<section id="policy" class="section">'
        "<h1>Policy Findings</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["policy"])}</p>'
        f"{_table(['Severity', 'Message', 'Source File', 'Policy ID', 'Policy Status'], rows, 'None detected.')}"
        "</section>"
    )


def _prompt_surfaces(items: Any) -> str:
    rows = [
        [
            str(_dict(item).get("path", "")),
            str(_dict(item).get("type", "")),
            _badge(str(_dict(item).get("confidence", "")), "confidence"),
        ]
        for item in _list(items)
    ]
    return (
        '<section id="prompts" class="section">'
        "<h1>Prompt Files</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["prompts"])}</p>'
        f"{_table(['Path', 'Type', 'Confidence'], rows, 'None detected.')}"
        "</section>"
    )


def _dependencies(items: Any) -> str:
    rows = [
        [
            str(_dict(item).get("name", "")),
            str(_dict(item).get("category", "")),
            str(_dict(item).get("path", "")),
            _badge(str(_dict(item).get("confidence", "")), "confidence"),
        ]
        for item in _list(items)
    ]
    return (
        '<section id="dependencies" class="section">'
        "<h1>Dependencies</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["dependencies"])}</p>'
        f"{_table(['Name', 'Category', 'Path', 'Confidence'], rows, 'None detected.')}"
        "</section>"
    )


def _secret_leaks(items: Any) -> str:
    rows = []
    for item in _list(items):
        finding = _dict(item)
        rows.append(
            [
                _badge(str(finding.get("severity", ""))),
                str(finding.get("provider", "")),
                str(finding.get("category", "")),
                str(finding.get("path", "")),
                str(finding.get("line", "")),
                _badge(str(finding.get("confidence", "")), "confidence"),
                str(finding.get("title", "")),
                str(finding.get("redacted_evidence", "")),
                str(finding.get("suggested_action", "")),
            ]
        )
    return (
        '<section id="secret-leaks" class="section">'
        "<h1>Secret Leak Findings</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["secret-leaks"])}</p>'
        f"{_table(_secret_leak_headers(), rows, 'None detected.')}"
        "</section>"
    )


def _policy_workbench(bom: dict[str, Any]) -> str:
    data = _policy_builder_data(bom)
    groups = [
        ("Providers", "provider", data["providers"]),
        ("Models", "model", data["models"]),
        ("Frameworks", "framework", data["frameworks"]),
        ("Reachable Capabilities", "capability", data["capabilities"]),
        ("MCP Servers", "mcp", data["mcp_servers"]),
        ("Secret References", "secret", data["secrets"]),
        ("Policy Gaps", "policy_gap", data["policy_gaps"]),
    ]
    body = "".join(_workbench_group(title, kind, values) for title, kind, values in groups)
    initial_policy = escape(_initial_policy_toml(data))
    return (
        '<section id="policy-workbench" class="section policy-workbench">'
        "<h1>Policy Workbench</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["policy-workbench"])}</p>'
        '<p class="subtle">'
        "Use the controls to turn current findings into a starter policy. "
        "Run the policy in advisory mode first; add --enforce-policy only after review."
        "</p>"
        '<div class="workbench-grid">'
        f'<div class="workbench-controls">{body}</div>'
        '<div class="policy-output">'
        "<h2>Generated aigenguard.toml</h2>"
        '<textarea id="policy-toml" readonly spellcheck="false">'
        f"{initial_policy}"
        "</textarea>"
        '<div class="button-row">'
        '<button type="button" id="copy-policy">Copy policy</button>'
        '<button type="button" id="download-policy">Download aigenguard.toml</button>'
        "</div>"
        "<h2>Follow-up commands</h2>"
        "<pre><code>aigenguard scan . --policy aigenguard.toml --html --open\n"
        "aigenguard scan . --policy aigenguard.toml --pretty\n"
        "aigenguard scan . --policy aigenguard.toml --enforce-policy</code></pre>"
        "<h2>Local guard</h2>"
        '<p class="subtle">'
        "advisory warns but allows commits; confirm asks before committing when "
        "violations exist; enforce blocks commits when violations exist."
        "</p>"
        "<pre><code>aigenguard install-hook --policy aigenguard.toml --mode advisory\n"
        "aigenguard install-hook --policy aigenguard.toml --mode confirm\n"
        "aigenguard install-hook --policy aigenguard.toml --mode enforce</code></pre>"
        "</div>"
        "</div>"
        "</section>"
    )


def _workbench_group(title: str, kind: str, values: list[str]) -> str:
    if not values:
        body = '<p class="empty compact">None detected.</p>'
    else:
        body = "".join(_workbench_item(kind, index, value) for index, value in enumerate(values))
    return (
        '<fieldset class="workbench-group">'
        f"<legend>{escape(title)}</legend>"
        f"{body}"
        "</fieldset>"
    )


def _workbench_item(kind: str, index: int, value: str) -> str:
    safe_value = escape(value, quote=True)
    name = f"policy-{kind}-{index}"
    controls = []
    default_action = "warn" if kind in {"secret", "policy_gap"} else "ignore"
    for action in _workbench_actions(kind):
        checked = " checked" if action == default_action else ""
        controls.append(
            '<label>'
            f'<input type="radio" name="{name}" data-kind="{escape(kind)}" '
            f'data-action="{action}" data-value="{safe_value}"{checked}> '
            f"{escape(action)}"
            "</label>"
        )
    return (
        '<div class="workbench-item">'
        f'<span title="{safe_value}">{safe_value}</span>'
        f'<div class="choice-row">{"".join(controls)}</div>'
        "</div>"
    )


def _workbench_actions(kind: str) -> tuple[str, ...]:
    if kind in {"provider", "model", "framework", "mcp"}:
        return ("allow", "deny", "ignore")
    if kind == "capability":
        return ("deny", "ignore")
    return ("warn", "ignore")


def _policy_builder_data(bom: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "providers": _names(bom.get("providers")),
        "models": _names(bom.get("models")),
        "frameworks": _names(bom.get("frameworks")),
        "capabilities": _reachable_capability_names(bom.get("reachable_capabilities")),
        "mcp_servers": _names(bom.get("mcp_servers")),
        "secrets": _names(bom.get("secret_references")),
        "policy_gaps": _policy_gap_names(bom.get("policy_findings")),
    }


def _names(items: Any) -> list[str]:
    values = []
    seen = set()
    for item in _list(items):
        value = str(_dict(item).get("name", "")).strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return sorted(values)


def _reachable_capability_names(items: Any) -> list[str]:
    values = []
    seen = set()
    for item in _list(items):
        value = str(_dict(item).get("capability", "")).strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return sorted(values)


def _policy_gap_names(items: Any) -> list[str]:
    values = []
    seen = set()
    for item in _list(items):
        finding = _dict(item)
        severity = str(finding.get("severity", "low")).strip()
        message = str(finding.get("message", "")).strip()
        value = f"{severity}: {message}" if message else severity
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return sorted(values)


def _initial_policy_toml(data: dict[str, list[str]]) -> str:
    del data
    return starter_policy_toml(strict=False)


def _policy_workbench_script(bom: dict[str, Any]) -> str:
    data = _json_for_script(_policy_builder_data(bom))
    return (
        "<script>"
        f"const aigenguardPolicyData = {data};"
        r"""
(function () {
  const area = document.getElementById("policy-toml");
  if (!area) return;
  const tomlString = function (value) {
    return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  };
  const tomlArray = function (values) {
    return "[" + values.map(tomlString).join(", ") + "]";
  };
  const selected = function (kind, action) {
    return Array.from(document.querySelectorAll(
      'input[data-kind="' + kind + '"][data-action="' + action + '"]:checked'
    )).map(function (input) { return input.getAttribute("data-value") || ""; });
  };
  const warnSelected = function (kind) {
    return selected(kind, "warn").length > 0;
  };
  const render = function () {
    const lines = [
      "[risk]",
      'warn_on = "high"',
      "",
      "[providers]",
      "allow = " + tomlArray(selected("provider", "allow")),
      "deny = " + tomlArray(selected("provider", "deny")),
      "",
      "[models]",
      "allow = " + tomlArray(selected("model", "allow")),
      "deny = " + tomlArray(selected("model", "deny")),
      "",
      "[frameworks]",
      "allow = " + tomlArray(selected("framework", "allow")),
      "deny = " + tomlArray(selected("framework", "deny")),
      "",
      "[capabilities]",
      "deny = " + tomlArray(selected("capability", "deny")),
      "",
      "[mcp]",
      "allow_servers = " + tomlArray(selected("mcp", "allow")),
      "deny_servers = " + tomlArray(selected("mcp", "deny")),
      "warn_on_unknown_server = true",
      "require_policy_for_risky_servers = true",
      "",
      "[secrets]",
      "warn_on_detected = "
        + ((aigenguardPolicyData.secrets.length === 0 || warnSelected("secret")) ? "true" : "false"),
      "",
      "[policy_gaps]",
      'warn_on = "'
        + ((aigenguardPolicyData.policy_gaps.length === 0 || warnSelected("policy_gap"))
          ? "medium" : "critical") + '"',
      ""
    ];
    area.value = lines.join("\n");
  };
  document.querySelectorAll("#policy-workbench input").forEach(function (input) {
    input.addEventListener("change", render);
  });
  const copyButton = document.getElementById("copy-policy");
  if (copyButton && navigator.clipboard) {
    copyButton.addEventListener("click", function () {
      navigator.clipboard.writeText(area.value);
    });
  }
  const downloadButton = document.getElementById("download-policy");
  if (downloadButton) {
    downloadButton.addEventListener("click", function () {
      const blob = new Blob([area.value], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "aigenguard.toml";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    });
  }
  render();
}());
"""
        "</script>"
    )


def _capability_graph(graph: dict[str, Any]) -> str:
    node_rows = [
        [
            str(_dict(item).get("id", "")),
            str(_dict(item).get("type", "")),
            str(_dict(item).get("name", "")),
        ]
        for item in _list(graph.get("nodes"))
    ]
    edge_rows = [
        [
            str(_dict(item).get("source", "")),
            str(_dict(item).get("target", "")),
            str(_dict(item).get("type", "")),
        ]
        for item in _list(graph.get("edges"))
    ]
    return (
        '<section id="graph" class="section">'
        "<h1>Capability Graph</h1>"
        f'<p class="section-lede">{escape(SECTION_HELP["graph"])}</p>'
        "<h2>Nodes</h2>"
        f"{_table(['ID', 'Type', 'Name'], node_rows, 'None detected.')}"
        "<h2>Edges</h2>"
        f"{_table(['Source', 'Target', 'Type'], edge_rows, 'None detected.')}"
        "</section>"
    )


def _model_headers() -> list[str]:
    return ["Model", "Type", "Source File", "Confidence", "Evidence"]


def _mcp_headers() -> list[str]:
    return [
        "Name",
        "Path",
        "Command",
        "Args",
        "Package",
        "Transport",
        "Env Names",
        "Risk",
        "Categories",
        "Rationale",
        "Policy Status",
    ]


def _reachable_headers() -> list[str]:
    return [
        "Capability",
        "Reachable From",
        "Source File",
        "Risk",
        "Confidence",
        "Score",
        "Paths",
        "MCP Server",
        "Mitigations",
        "Rationale",
        "Policy Status",
    ]


def _secret_leak_headers() -> list[str]:
    return [
        "Severity",
        "Provider",
        "Category",
        "Path",
        "Line",
        "Confidence",
        "Finding",
        "Evidence",
        "Action",
    ]


def _table(headers: list[str], rows: list[list[Any]], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{escape(empty)}</p>'
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{_table_cell(cell)}</td>" for cell in row)
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        '<div class="table-wrap">'
        "<table>"
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "</div>"
    )


def _table_cell(value: Any) -> str:
    if isinstance(value, SafeHtml):
        return str(value)
    return escape(str(value))


def _bullets(items: list[Any], empty: str) -> str:
    if not items:
        return f'<p class="empty">{escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{escape(str(item))}</li>" for item in items) + "</ul>"


def _badge(label: str, kind: str = "severity") -> str:
    if not label:
        return ""
    return SafeHtml(f'<span class="badge {_badge_class(label, kind)}">{escape(label)}</span>')


def _policy_status_badge(value: object) -> str:
    label = _policy_status_label(value)
    if not label:
        return ""
    return _badge(label, "policy-status")


def _policy_status_label(value: object) -> str:
    labels = {
        "undocumented": "undocumented",
        "documented_by_repository_policy": "documented by repository policy",
        "policy_warning": "policy warning",
        "policy_violation": "policy violation",
        "not_applicable": "not applicable",
    }
    return labels.get(str(value), "")


def _badge_class(label: str, kind: str = "severity") -> str:
    return f"{kind}-{_class_token(label)}"


def _severity_class(label: str) -> str:
    return f"ring-{_class_token(label)}"


def _class_token(value: str) -> str:
    token = "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")
    return token or "unknown"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any, default: int) -> int:
    return value if isinstance(value, int) else default


def _json_for_script(value: Any) -> str:
    return (
        json.dumps(value, sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _css() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-2: #f0f4f8;
  --text: #17202a;
  --muted: #5f6b7a;
  --line: #d9e0e8;
  --low: #2f9e74;
  --medium: #b7791f;
  --high: #c2410c;
  --critical: #b91c1c;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family:
    Inter,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
  line-height: 1.5;
}
.layout {
  display: grid;
  grid-template-columns: 248px minmax(0, 1fr);
  min-height: 100vh;
}
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 28px 22px;
  background: #17202a;
  border-right: 1px solid var(--line);
}
.brand {
  font-size: 1.35rem;
  font-weight: 800;
  letter-spacing: 0;
  color: #ffffff;
}
.subtitle {
  margin: 4px 0 28px;
  color: #b9c3d0;
  font-size: .9rem;
}
nav {
  display: grid;
  gap: 6px;
}
nav a {
  color: #dbe2ea;
  text-decoration: none;
  padding: 9px 10px;
  border-radius: 8px;
}
nav a:hover {
  color: #ffffff;
  background: #263342;
}
.content {
  width: min(1200px, 100%);
  padding: 34px 30px 56px;
}
.section {
  padding: 28px 0 36px;
  border-bottom: 1px solid var(--line);
}
.section-heading {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}
h1, h2 {
  letter-spacing: 0;
  line-height: 1.2;
}
h1 {
  margin: 0 0 18px;
  font-size: 1.55rem;
}
h2 {
  margin: 22px 0 10px;
  color: #243140;
  font-size: 1rem;
}
.section-lede,
.subtle {
  max-width: 860px;
  margin: 0 0 16px;
  color: var(--muted);
}
.overview-grid {
  display: grid;
  grid-template-columns: minmax(260px, 420px) 1fr;
  gap: 18px;
  align-items: stretch;
}
.score-panel,
.metric,
.meta-grid > div,
.explanation,
.workflow-card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.score-panel {
  display: flex;
  gap: 20px;
  align-items: center;
  padding: 22px;
}
.score-ring {
  --score-color: var(--low);
  display: grid;
  place-items: center;
  width: 132px;
  height: 132px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: conic-gradient(var(--score-color) calc(var(--score) * 1%), #d6dde6 0);
}
.score-ring span {
  display: grid;
  place-items: center;
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: var(--surface);
  color: var(--text);
  font-size: 2rem;
  font-weight: 800;
}
.ring-low { --score-color: var(--low); }
.ring-medium { --score-color: var(--medium); }
.ring-high { --score-color: var(--high); }
.ring-critical { --score-color: var(--critical); }
.score-copy h2 {
  margin: 0 0 6px;
  font-size: 1.15rem;
}
.score-copy p {
  margin: 0;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.metric {
  padding: 18px;
}
.metric-value {
  display: block;
  font-size: 1.7rem;
  font-weight: 800;
}
.metric-label {
  color: var(--muted);
}
.meta-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}
.meta-grid > div {
  padding: 14px 16px;
}
.meta-grid span {
  display: block;
  color: var(--muted);
  font-size: .84rem;
}
.meta-grid strong {
  overflow-wrap: anywhere;
}
.explanation {
  margin-top: 14px;
  padding: 16px;
}
.workflow-card {
  padding: 16px;
}
.workflow-card pre {
  margin-top: 14px;
}
.explanation p {
  margin: 0;
  color: var(--muted);
}
.explanation p + p {
  margin-top: 8px;
}
ol {
  margin: 0;
  padding-left: 24px;
  color: #243140;
}
ol li + li {
  margin-top: 6px;
}
.table-wrap {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
}
table {
  width: 100%;
  min-width: 680px;
  border-collapse: collapse;
}
th, td {
  padding: 11px 13px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
th {
  color: #405064;
  background: var(--surface-2);
  font-size: .78rem;
  text-transform: uppercase;
}
td {
  color: var(--text);
  overflow-wrap: anywhere;
}
tbody tr:last-child td {
  border-bottom: 0;
}
.badge {
  display: inline-block;
  min-width: 64px;
  padding: 3px 8px;
  border-radius: 999px;
  font-size: .75rem;
  font-weight: 700;
  text-align: center;
  text-transform: uppercase;
}
.severity-low, .confidence-low { color: #052e22; background: var(--low); }
.severity-medium, .confidence-medium { color: #ffffff; background: var(--medium); }
.severity-high, .confidence-high { color: #ffffff; background: var(--high); }
.severity-critical { color: #ffffff; background: var(--critical); }
.status-passed, .status-passed-with-warnings { color: #052e22; background: var(--low); }
.status-failed { color: #ffffff; background: var(--high); }
.empty {
  margin: 0;
  padding: 14px 16px;
  color: var(--muted);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
}
ul {
  margin: 0;
  padding-left: 22px;
  color: #243140;
}
li + li {
  margin-top: 4px;
}
.workbench-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(340px, .9fr);
  gap: 18px;
  align-items: start;
}
.workbench-controls {
  display: grid;
  gap: 12px;
}
.workbench-group {
  margin: 0;
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
}
.workbench-group legend {
  padding: 0 6px;
  color: #243140;
  font-weight: 700;
}
.workbench-item {
  display: grid;
  gap: 8px;
  padding: 10px 0;
  border-top: 1px solid var(--line);
}
.workbench-item:first-of-type {
  border-top: 0;
}
.workbench-item > span {
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .88rem;
}
.choice-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
}
.choice-row label {
  color: var(--muted);
  font-size: .88rem;
}
.policy-output {
  position: sticky;
  top: 20px;
}
.policy-output textarea {
  width: 100%;
  min-height: 430px;
  resize: vertical;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .88rem;
  line-height: 1.45;
}
.button-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 10px 0 16px;
}
button {
  padding: 9px 12px;
  border: 1px solid #405064;
  border-radius: 8px;
  background: #243140;
  color: #ffffff;
  font: inherit;
  cursor: pointer;
}
button:hover {
  background: #17202a;
}
pre {
  margin: 0;
  padding: 12px;
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
}
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .88rem;
}
.compact {
  padding: 8px 10px;
}
@media (max-width: 860px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar {
    position: static;
    height: auto;
    padding: 18px;
  }
  nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .content { padding: 22px 16px 42px; }
  .overview-grid, .meta-grid { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .workbench-grid { grid-template-columns: 1fr; }
  .policy-output { position: static; }
}
@media print {
  body { background: #fff; color: #111827; }
  .layout { display: block; }
  .sidebar { display: none; }
  .content { width: 100%; padding: 0; }
  .section { break-inside: avoid; border-bottom-color: #d1d5db; }
  .score-panel, .metric, .meta-grid > div, .explanation, .workflow-card, .table-wrap, .empty {
    background: #fff;
    border-color: #d1d5db;
  }
  .score-ring span { background: #fff; color: #111827; }
  th { background: #f3f4f6; color: #111827; }
  td, h2, ul { color: #111827; }
  .score-copy p, .metric-label, .meta-grid span, .empty { color: #4b5563; }
  a { color: #111827; }
}
""".strip()
