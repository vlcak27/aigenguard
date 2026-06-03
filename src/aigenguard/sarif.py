"""SARIF export for AigenGuard."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from . import __version__


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}
DIFF_SECURITY_SEVERITY = {"critical": "9.0", **SECURITY_SEVERITY}


def write_sarif_report(bom: dict[str, Any], output_dir: str | Path, pretty: bool = False) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    sarif_path = out / "agentbom.sarif"
    indent = 2 if pretty else None
    sarif_path.write_text(
        json.dumps(render_sarif(bom), indent=indent, sort_keys=pretty) + "\n",
        encoding="utf-8",
    )
    return sarif_path


def render_sarif(bom: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    grouped_results: dict[str, dict[str, Any]] = {}

    for risk in bom.get("risks", []):
        severity = risk["severity"]
        rule_id = f"risk.{severity}"
        _register_rule(
            rules,
            rule_id,
            name=f"{severity.title()} aggregate risk",
            severity=severity,
            summary=risk["reason"],
            help_text=(
                "AigenGuard emits aggregate risk findings when static analysis detects "
                "repository-level patterns that require security review."
            ),
            remediation=(
                "Review the detailed AigenGuard JSON and Markdown output, then reduce exposed "
                "agent capabilities or document compensating controls."
            ),
        )
        _add_result(grouped_results, rule_id, severity, risk["reason"])

    for item in bom.get("reachable_capabilities", []):
        severity = item["risk"]
        capability = item["capability"]
        rule_id = f"reachable.{capability}"
        message = f"{item['reachable_from']} reaches {capability} with {severity} risk"
        _register_rule(
            rules,
            rule_id,
            name=f"Reachable capability: {capability}",
            severity=severity,
            summary=f"An agent actor appears able to reach {capability}.",
            help_text=(
                "Reachability findings connect detected models, frameworks, or tool "
                "configuration to sensitive capabilities using deterministic static evidence."
            ),
            remediation=(
                "Constrain or remove the reachable capability, isolate it behind an explicit "
                "approval or sandbox boundary, and document expected use in repository policy."
            ),
        )
        _add_result(
            grouped_results,
            rule_id,
            severity,
            message,
            source_file=item["source_file"],
            properties=_policy_status_properties(item),
        )

    for server in bom.get("mcp_servers", []):
        if not isinstance(server, dict) or server.get("risk") != "high":
            continue
        name = str(server.get("name", "unknown"))
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            categories = []
        category_text = ", ".join(str(category) for category in categories) or "high risk"
        rule_id = f"mcp.high_risk_server.{_slug(name)}"
        message = f"High-risk MCP server {name} exposes {category_text}"
        _register_rule(
            rules,
            rule_id,
            name=f"High-risk MCP server: {name}",
            severity="high",
            summary=f"MCP server {name} has high-risk tool exposure.",
            help_text=(
                "AigenGuard classifies MCP server risk from JSON configuration metadata "
                "such as command, package, args, transport, and env variable names."
            ),
            remediation=(
                "Remove the MCP server, restrict it with policy and sandboxing, or replace "
                "it with a narrower server."
            ),
        )
        _add_result(
            grouped_results,
            rule_id,
            "high",
            message,
            source_file=str(server.get("path", "")),
            properties={
                "agentbom.mcp_server": name,
                **_policy_status_properties(server),
            },
        )

    for finding in bom.get("policy_findings", []):
        severity = finding["severity"]
        rule_id = f"policy.{_slug(finding['message'])}"
        _register_rule(
            rules,
            rule_id,
            name=finding["message"],
            severity=severity,
            summary="Policy finding detected by AigenGuard.",
            help_text=(
                "Policy findings indicate missing controls or custom policy violations "
                "for AI agent behavior."
            ),
            remediation=(
                "Update repository policy, add required controls, or reduce the capability "
                "that triggered the policy finding."
            ),
        )
        _add_result(
            grouped_results,
            rule_id,
            severity,
            finding["message"],
            source_file=finding["source_file"],
            properties=_policy_status_properties(finding),
        )

    for finding in bom.get("secret_leak_findings", []):
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "critical"))
        provider = str(finding.get("provider", "secret"))
        title = str(finding.get("title", "Possible secret value"))
        rule_id = f"secret_leak.{_slug(provider)}.{_slug(str(finding.get('category', 'secret')))}"
        _register_rule(
            rules,
            rule_id,
            name=title,
            severity=severity,
            summary=title,
            help_text=(
                "AigenGuard detected a likely AI/API credential value with deterministic "
                "offline pattern matching. The value is redacted from all outputs."
            ),
            remediation=str(finding.get("suggested_action", "Remove the key and rotate it.")),
        )
        _add_result(
            grouped_results,
            rule_id,
            severity,
            title,
            source_file=str(finding.get("path", "")),
            line=finding.get("line"),
            properties={"agentbom.secret_provider": provider},
        )

    diff = bom.get("diff", {})
    if isinstance(diff, dict):
        for finding in diff.get("introduced", []):
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "low"))
            category = str(finding.get("category", "finding"))
            title = str(finding.get("title", "finding"))
            rule_id = f"diff.introduced.{category}.{finding.get('id', '')}"
            _register_rule(
                rules,
                rule_id,
                name=f"Introduced {category}: {title}",
                severity=severity,
                summary=f"New {category} finding introduced since the baseline.",
                help_text=(
                    "Diff findings are created by comparing the current AigenGuard report "
                    "against a supplied baseline JSON report."
                ),
                remediation=(
                    "Review the introduced finding, update policy controls if it is expected, "
                    "or remove the newly introduced risk."
                ),
            )
            _add_result(
                grouped_results,
                rule_id,
                severity,
                f"Introduced {category}: {title}",
                source_file=str(finding.get("source_file", "")),
                properties={"agentbom.diff_id": str(finding.get("id", ""))},
            )

    sorted_rules = sorted(rules.values(), key=lambda item: item["id"])
    rule_indexes = {rule["id"]: index for index, rule in enumerate(sorted_rules)}
    results = [
        _with_rule_index(result, rule_indexes)
        for result in sorted(grouped_results.values(), key=lambda item: item["ruleId"])
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AigenGuard",
                        "informationUri": "https://github.com/vlcak27/aigenguard",
                        "semanticVersion": __version__,
                        "rules": sorted_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _register_rule(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
    name: str,
    severity: str,
    summary: str,
    help_text: str,
    remediation: str,
) -> None:
    if rule_id in rules:
        return
    rules[rule_id] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": summary},
        "fullDescription": {"text": help_text},
        "help": {"text": f"{help_text}\n\nRemediation: {remediation}"},
        "defaultConfiguration": {"level": _level(severity)},
        "properties": {
            "precision": "medium",
            "problem.severity": severity,
            "security-severity": DIFF_SECURITY_SEVERITY.get(
                severity, SECURITY_SEVERITY["low"]
            ),
            "tags": ["security", "ai-agent", "attack-surface"],
        },
    }


def _add_result(
    results: dict[str, dict[str, Any]],
    rule_id: str,
    severity: str,
    message: str,
    source_file: str | None = None,
    line: object = None,
    properties: dict[str, str] | None = None,
) -> None:
    result = results.setdefault(
        rule_id,
        {
            "ruleId": rule_id,
            "level": _level(severity),
            "message": {"text": message},
            "properties": {
                "problem.severity": severity,
                "security-severity": DIFF_SECURITY_SEVERITY.get(
                    severity, SECURITY_SEVERITY["low"]
                ),
            },
        },
    )
    if properties:
        _merge_result_properties(result, properties)
    locations = result.setdefault("locations", [])
    _append_unique(locations, _location(source_file, line))


def _merge_result_properties(
    result: dict[str, Any], properties: dict[str, str]
) -> None:
    target = result["properties"]
    conflicts = result.setdefault("_aigenguard_property_conflicts", set())
    if not isinstance(conflicts, set):
        return
    for key, value in properties.items():
        if key in conflicts:
            continue
        existing = target.get(key)
        if key not in target:
            target[key] = value
        elif existing != value:
            target.pop(key, None)
            conflicts.add(key)


def _policy_status_properties(item: dict[str, Any]) -> dict[str, str]:
    status = item.get("policy_status")
    if not isinstance(status, str) or not status:
        return {}
    return {"aigenguard.policy_status": status}


def _with_rule_index(result: dict[str, Any], rule_indexes: dict[str, int]) -> dict[str, Any]:
    copied = dict(result)
    copied.pop("_aigenguard_property_conflicts", None)
    copied["ruleIndex"] = rule_indexes[copied["ruleId"]]
    return copied


def _location(source_file: str | None, line: object = None) -> dict[str, Any]:
    start_line = line if isinstance(line, int) and line > 0 else 1
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": source_file or "repository",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {"startLine": start_line},
        }
    }


def _level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if item not in items:
        items.append(item)
