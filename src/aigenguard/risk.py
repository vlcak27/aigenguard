"""Risk scoring for AigenGuard findings."""

from __future__ import annotations

from typing import Any


def score_risks(
    capabilities: list[dict[str, str]],
    prompts: list[dict[str, str]],
    mcp_servers: list[dict[str, Any]],
    has_policy: bool,
) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    capability_names = {item["name"] for item in capabilities}

    if capability_names & {"shell", "code_execution", "autonomous_execution"}:
        risks.append(
            {
                "severity": "high",
                "reason": "shell, code execution, or autonomous execution capability detected",
            }
        )

    medium = capability_names & {"network", "database", "cloud"}
    if medium:
        risks.append(
            {
                "severity": "medium",
                "reason": "network, database, or cloud capability detected",
            }
        )

    if prompts and not has_policy:
        risks.append(
            {
                "severity": "low",
                "reason": "prompt files detected without a policy file",
            }
        )

    if any(server.get("risk") == "high" for server in mcp_servers):
        risks.append(
            {
                "severity": "high",
                "reason": "high-risk MCP server detected",
            }
        )

    return risks


def score_repository_risk(
    reachable_capabilities: list[dict[str, Any]],
    capabilities: list[dict[str, str]],
    secret_references: list[dict[str, str]],
    policy_findings: list[dict[str, str]],
) -> dict[str, object]:
    """Compute an aggregate repository risk score from normalized scanner findings."""
    score = 0
    rationale: list[str] = []
    capability_names = {item["name"] for item in capabilities}
    reachable_names = {item["capability"] for item in reachable_capabilities}

    reachable_score = _reachable_score(reachable_capabilities)
    if reachable_score:
        score += reachable_score
        rationale.append(_reachable_rationale(reachable_capabilities))

    if "autonomous_execution" in capability_names or "autonomous_execution" in reachable_names:
        score += 20
        rationale.append("autonomous execution is present or reachable")

    if (
        capability_names & {"shell", "code_execution"}
        or "code_execution" in reachable_names
        or _has_reachable_path(reachable_capabilities, "shell_execution")
    ):
        score += 25
        rationale.append("shell or code execution is present or reachable")

    if secret_references:
        score += 20
        rationale.append("secret references were detected")

    if _has_missing_policy_control(policy_findings):
        score += 15
        rationale.append("policy controls are missing or incomplete")

    score = min(score, 100)
    if not rationale:
        rationale.append("no repository-level risk factors detected")

    return {
        "score": score,
        "severity": _severity_bucket(score),
        "rationale": rationale,
    }


def _reachable_score(reachable_capabilities: list[dict[str, Any]]) -> int:
    risks = {str(item.get("risk", "")) for item in reachable_capabilities}
    if "high" in risks:
        return 30
    if "medium" in risks:
        return 20
    if "low" in risks:
        return 10
    return 0


def _reachable_rationale(reachable_capabilities: list[dict[str, Any]]) -> str:
    highest = "low"
    for severity in ("high", "medium", "low"):
        if any(item.get("risk") == severity for item in reachable_capabilities):
            highest = severity
            break
    capabilities = sorted(
        {
            str(item.get("capability"))
            for item in reachable_capabilities
            if item.get("risk") == highest and item.get("capability")
        }
    )
    if capabilities:
        return f"{highest}-risk reachable capability detected: {', '.join(capabilities)}"
    return f"{highest}-risk reachable capability detected"


def _has_reachable_path(reachable_capabilities: list[dict[str, Any]], path: str) -> bool:
    return any(path in item.get("paths", []) for item in reachable_capabilities)


def _has_missing_policy_control(policy_findings: list[dict[str, str]]) -> bool:
    for finding in policy_findings:
        message = finding.get("message", "").lower()
        policy_id = finding.get("policy_id", "")
        if "without" in message or "missing" in message or policy_id.startswith("require_"):
            return True
    return False


def _severity_bucket(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
