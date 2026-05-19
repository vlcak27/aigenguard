"""Policy validation for AgentBOM findings."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib
from typing import Any


CAPABILITY_ALIASES = {
    "autonomous-execution": "autonomous_execution",
    "autonomous_execution": "autonomous_execution",
    "code-execution": "code_execution",
    "code_execution": "code_execution",
    "cloud": "cloud",
    "cloud-access": "cloud",
    "cloud_access": "cloud",
    "database": "database",
    "database-access": "database",
    "database_access": "database",
    "mcp-tool-invocation": "mcp_tool_invocation",
    "mcp_tool_invocation": "mcp_tool_invocation",
    "network": "network",
    "network-access": "network",
    "network_access": "network",
    "shell": "shell",
    "shell-execution": "shell",
    "shell_execution": "shell",
}
HUMAN_APPROVAL_RE = re.compile(
    r"\b(human approval|human[- ]in[- ]the[- ]loop|approval required|manual approval)\b",
    re.IGNORECASE,
)
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_TOML_POLICY: dict[str, Any] = {
    "risk": {"warn_on": None},
    "providers": {"allow": [], "deny": []},
    "models": {"allow": [], "deny": []},
    "frameworks": {"allow": [], "deny": []},
    "capabilities": {"deny": []},
    "mcp": {
        "allow_servers": [],
        "deny_servers": [],
        "warn_on_unknown_server": True,
        "require_policy_for_risky_servers": True,
    },
    "secrets": {"warn_on_detected": True, "block_leaks": False},
    "policy_gaps": {"warn_on": None},
}


class PolicyError(ValueError):
    """Raised when a custom policy file cannot be parsed."""


def evaluate_policy_file(
    policy_path: str | Path,
    bom: dict[str, object],
    *,
    mode: str = "advisory",
    has_repository_policy: bool = False,
) -> dict[str, object]:
    """Load and evaluate a TOML policy against an AgentBOM report."""
    policy_file = Path(policy_path)
    policy = load_toml_policy(policy_file)
    return evaluate_policy(
        policy,
        bom,
        policy_file=str(policy_file),
        mode=mode,
        has_repository_policy=has_repository_policy,
    )


def load_toml_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file does not exist: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"policy path is not a file: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file must be UTF-8 text: {path}") from exc
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        location = f" at line {line}, column {column}" if line and column else ""
        raise PolicyError(f"invalid policy TOML{location}: {path}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy file must contain a TOML table: {path}")
    return normalize_toml_policy(raw)


def normalize_toml_policy(raw: dict[str, Any]) -> dict[str, Any]:
    policy = {
        section: dict(values) if isinstance(values, dict) else values
        for section, values in DEFAULT_TOML_POLICY.items()
    }
    for section in raw:
        if section not in DEFAULT_TOML_POLICY:
            raise PolicyError(f"unsupported policy section: [{section}]")
        if not isinstance(raw[section], dict):
            raise PolicyError(f"policy section [{section}] must be a table")
        policy[section].update(raw[section])

    _validate_severity(policy["risk"].get("warn_on"), "risk.warn_on", allow_none=True)
    _validate_severity(
        policy["policy_gaps"].get("warn_on"), "policy_gaps.warn_on", allow_none=True
    )
    for section in ("providers", "models", "frameworks"):
        for key in ("allow", "deny"):
            policy[section][key] = _string_list(policy[section].get(key), f"{section}.{key}")
    policy["capabilities"]["deny"] = _string_list(
        policy["capabilities"].get("deny"), "capabilities.deny"
    )
    policy["mcp"]["allow_servers"] = _string_list(
        policy["mcp"].get("allow_servers"), "mcp.allow_servers"
    )
    policy["mcp"]["deny_servers"] = _string_list(
        policy["mcp"].get("deny_servers"), "mcp.deny_servers"
    )
    policy["mcp"]["warn_on_unknown_server"] = _bool_value(
        policy["mcp"].get("warn_on_unknown_server"), "mcp.warn_on_unknown_server"
    )
    policy["mcp"]["require_policy_for_risky_servers"] = _bool_value(
        policy["mcp"].get("require_policy_for_risky_servers"),
        "mcp.require_policy_for_risky_servers",
    )
    policy["secrets"]["warn_on_detected"] = _bool_value(
        policy["secrets"].get("warn_on_detected"), "secrets.warn_on_detected"
    )
    policy["secrets"]["block_leaks"] = _bool_value(
        policy["secrets"].get("block_leaks"), "secrets.block_leaks"
    )
    return policy


def evaluate_policy(
    policy: dict[str, Any],
    bom: dict[str, object],
    *,
    policy_file: str | None = None,
    mode: str = "advisory",
    has_repository_policy: bool = False,
) -> dict[str, object]:
    violations: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    _evaluate_repository_risk(policy, bom, violations)
    _evaluate_named_findings(
        policy["providers"],
        bom.get("providers", []),
        "providers",
        "Provider",
        "medium",
        violations,
    )
    _evaluate_named_findings(
        policy["models"],
        bom.get("models", []),
        "models",
        "Model",
        "medium",
        violations,
    )
    _evaluate_named_findings(
        policy["frameworks"],
        bom.get("frameworks", []),
        "frameworks",
        "Framework",
        "medium",
        violations,
    )
    _evaluate_capabilities(policy, bom, violations)
    _evaluate_mcp(policy, bom, violations, warnings, has_repository_policy=has_repository_policy)
    _evaluate_secrets(policy, bom, warnings)
    _evaluate_policy_gaps(policy, bom, warnings)
    violations = _dedupe_policy_items(violations)
    warnings = _dedupe_policy_items(warnings)

    return {
        "passed": not violations,
        "mode": mode,
        "policy_file": policy_file,
        "violations": violations,
        "warnings": warnings,
    }


def _evaluate_repository_risk(
    policy: dict[str, Any], bom: dict[str, object], violations: list[dict[str, str]]
) -> None:
    threshold = policy["risk"].get("warn_on")
    if threshold is None:
        return
    risk = bom.get("repository_risk", {})
    if not isinstance(risk, dict):
        return
    severity = str(risk.get("severity", "low")).lower()
    if _at_or_above(severity, str(threshold)):
        violations.append(
            {
                "rule": "risk.warn_on",
                "severity": severity,
                "message": (
                    f"Repository risk is {severity}, policy warns on {threshold} or above."
                ),
                "source": "repository_risk",
                "suggested_remediation": "Review reachable capabilities and policy gaps.",
            }
        )


def _evaluate_named_findings(
    section: dict[str, Any],
    items: object,
    rule_prefix: str,
    label: str,
    severity: str,
    violations: list[dict[str, str]],
) -> None:
    allow = {_normalize_name(value) for value in section.get("allow", [])}
    deny = {_normalize_name(value) for value in section.get("deny", [])}
    for item in _list(items):
        if not isinstance(item, dict):
            continue
        name = _normalize_name(str(item.get("name", "")))
        if not name:
            continue
        source = _finding_source(item)
        if name in deny:
            violations.append(
                {
                    "rule": f"{rule_prefix}.deny",
                    "severity": severity,
                    "message": f"{label} denied by policy: {name}.",
                    "source": source,
                    "suggested_remediation": f"Remove {name} or update the policy denial.",
                }
            )
        elif allow and name not in allow:
            violations.append(
                {
                    "rule": f"{rule_prefix}.allow",
                    "severity": severity,
                    "message": f"{label} not allowed by policy: {name}.",
                    "source": source,
                    "suggested_remediation": f"Add {name} to the allow list or remove it.",
                }
            )


def _evaluate_capabilities(
    policy: dict[str, Any], bom: dict[str, object], violations: list[dict[str, str]]
) -> None:
    denied = {
        _normalize_reachable_capability(value)
        for value in policy["capabilities"].get("deny", [])
        if _normalize_reachable_capability(value)
    }
    if not denied:
        return
    for item in _list(bom.get("reachable_capabilities", [])):
        if not isinstance(item, dict):
            continue
        capability = _normalize_reachable_capability(str(item.get("capability", "")))
        if capability in denied:
            severity = str(item.get("risk", "high"))
            violations.append(
                {
                    "rule": "capabilities.deny",
                    "severity": severity if severity in SEVERITY_ORDER else "high",
                    "message": f"Denied reachable capability detected: {capability}.",
                    "source": _finding_source(item),
                    "suggested_remediation": (
                        "Remove the reachable path, require approval, or update policy."
                    ),
                }
            )


def _evaluate_mcp(
    policy: dict[str, Any],
    bom: dict[str, object],
    violations: list[dict[str, str]],
    warnings: list[dict[str, str]],
    *,
    has_repository_policy: bool,
) -> None:
    mcp_policy = policy["mcp"]
    allow = {_normalize_name(value) for value in mcp_policy.get("allow_servers", [])}
    deny = {_normalize_name(value) for value in mcp_policy.get("deny_servers", [])}
    for item in _list(bom.get("mcp_servers", [])):
        if not isinstance(item, dict):
            continue
        name = _normalize_name(str(item.get("name", "")))
        if not name:
            continue
        source = _finding_source(item)
        if name in deny:
            violations.append(
                {
                    "rule": "mcp.deny_servers",
                    "severity": "high",
                    "message": f"MCP server denied by policy: {name}.",
                    "source": source,
                    "suggested_remediation": "Remove the MCP server or update the deny list.",
                }
            )
        elif allow and name not in allow:
            violations.append(
                {
                    "rule": "mcp.allow_servers",
                    "severity": "medium",
                    "message": f"MCP server not allowed by policy: {name}.",
                    "source": source,
                    "suggested_remediation": "Add the MCP server to allow_servers or remove it.",
                }
            )

        categories = _list(item.get("risk_categories"))
        if (
            mcp_policy.get("warn_on_unknown_server")
            and "unknown_custom_server" in {str(category) for category in categories}
        ):
            warnings.append(
                {
                    "rule": "mcp.warn_on_unknown_server",
                    "severity": "medium",
                    "message": f"Unknown MCP server detected: {name}.",
                    "source": source,
                    "suggested_remediation": "Review the custom MCP server before allowing it.",
                }
            )
        if (
            mcp_policy.get("require_policy_for_risky_servers")
            and str(item.get("risk", "low")) == "high"
            and name not in allow
            and not has_repository_policy
        ):
            violations.append(
                {
                    "rule": "mcp.require_policy_for_risky_servers",
                    "severity": "high",
                    "message": f"Risky MCP server lacks policy evidence: {name}.",
                    "source": source,
                    "suggested_remediation": (
                        "Document restrictions or add the server to mcp.allow_servers."
                    ),
                }
            )


def _evaluate_secrets(
    policy: dict[str, Any], bom: dict[str, object], warnings: list[dict[str, str]]
) -> None:
    if not policy["secrets"].get("warn_on_detected"):
        return
    for item in _list(bom.get("secret_references", [])):
        if not isinstance(item, dict):
            continue
        source = _finding_source(item)
        warnings.append(
            {
                "rule": "secrets.warn_on_detected",
                "severity": "medium",
                "message": (
                    "Secret reference detected and secrets.warn_on_detected is enabled."
                ),
                "source": source,
                "suggested_remediation": "Confirm credentials are stored outside the repository.",
            }
        )


def _evaluate_policy_gaps(
    policy: dict[str, Any], bom: dict[str, object], warnings: list[dict[str, str]]
) -> None:
    threshold = policy["policy_gaps"].get("warn_on")
    if threshold is None:
        return
    for item in _list(bom.get("policy_findings", [])):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "low"))
        if _at_or_above(severity, str(threshold)):
            warnings.append(
                {
                    "rule": "policy_gaps.warn_on",
                    "severity": severity if severity in SEVERITY_ORDER else str(threshold),
                    "message": "Policy gap detected at or above threshold.",
                    "source": _finding_source(item),
                    "suggested_remediation": "Resolve the policy finding or document acceptance.",
                }
            )


def validate_policies(
    prompts: list[dict[str, str]],
    capabilities: list[dict[str, str]],
    mcp_servers: list[dict[str, str]],
    has_policy: bool,
) -> list[dict[str, str]]:
    if has_policy:
        return []

    findings: list[dict[str, str]] = []
    for prompt in prompts:
        _append_unique(
            findings,
            {
                "severity": "low",
                "message": "prompt file detected without security policy",
                "source_file": prompt["path"],
            },
        )

    for capability in capabilities:
        if capability["name"] == "shell":
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": "shell execution detected without restrictions",
                    "source_file": capability["path"],
                },
            )
        if capability["name"] == "cloud":
            _append_unique(
                findings,
                {
                    "severity": "medium",
                    "message": "cloud access detected without policy file",
                    "source_file": capability["path"],
                },
            )

    for server in mcp_servers:
        _append_unique(
            findings,
            {
                "severity": "medium",
                "message": "MCP config detected without policy documentation",
                "source_file": server["path"],
            },
        )
        if server.get("risk") == "high":
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": (
                        "high-risk MCP server detected without policy restrictions: "
                        f"{server['name']}"
                    ),
                    "source_file": server["path"],
                },
            )

    return findings


def validate_custom_policy(
    policy_path: str | Path,
    bom: dict[str, object],
    has_human_approval: bool = False,
) -> list[dict[str, str]]:
    policy_file = Path(policy_path)
    policy = load_policy(policy_file)
    findings: list[dict[str, str]] = []

    denied_capabilities = {
        normalized
        for item in policy.get("deny_capabilities", [])
        if (normalized := normalize_capability(str(item))) is not None
    }
    denied_mcp_server_names = {
        str(item).strip().lower()
        for item in policy.get("deny_mcp_servers", [])
        if str(item).strip()
    }
    denied_mcp_risk_categories = {
        normalize_mcp_risk_category(str(item))
        for item in policy.get("deny_mcp_risk_categories", [])
        if normalize_mcp_risk_category(str(item)) is not None
    }
    for capability in bom.get("capabilities", []):
        if not isinstance(capability, dict):
            continue
        name = normalize_capability(str(capability.get("name", "")))
        if name in denied_capabilities:
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": f"custom policy violation: denied capability {name}",
                    "source_file": str(capability.get("path", policy_file)),
                    "policy_id": "deny_capabilities",
                },
            )

    for server in bom.get("mcp_servers", []):
        if not isinstance(server, dict):
            continue
        server_name = str(server.get("name", "")).lower()
        if server_name in denied_mcp_server_names:
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": f"custom policy violation: denied MCP server {server_name}",
                    "source_file": str(server.get("path", policy_file)),
                    "policy_id": "deny_mcp_servers",
                },
            )
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            normalized = normalize_mcp_risk_category(str(category))
            if normalized in denied_mcp_risk_categories:
                _append_unique(
                    findings,
                    {
                        "severity": "high",
                        "message": (
                            "custom policy violation: denied MCP risk category "
                            f"{normalized}"
                        ),
                        "source_file": str(server.get("path", policy_file)),
                        "policy_id": "deny_mcp_risk_categories",
                    },
                )

    requirements = policy.get("require", {})
    if requirements.get("sandboxing") and not _has_sandboxing_dependency(bom):
        _append_unique(
            findings,
            {
                "severity": "high",
                "message": "custom policy violation: sandboxing is required",
                "source_file": str(policy_file),
                "policy_id": "require_sandboxing",
            },
        )
    if requirements.get("human_approval") and not has_human_approval:
        _append_unique(
            findings,
            {
                "severity": "high",
                "message": "custom policy violation: human approval is required",
                "source_file": str(policy_file),
                "policy_id": "require_human_approval",
            },
        )

    return findings


def load_policy(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"policy file does not exist: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"policy path is not a file: {path}")
    text = path.read_text(encoding="utf-8")
    return parse_policy_yaml(text)


def parse_policy_yaml(text: str) -> dict[str, object]:
    policy: dict[str, object] = {"deny_capabilities": [], "require": {}}
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not raw_line.startswith((" ", "\t")) and stripped.endswith(":"):
            section = stripped[:-1].strip()
            if section == "deny":
                section = "deny_capabilities"
            if section == "deny_capabilities":
                policy.setdefault("deny_capabilities", [])
            elif section in {"deny_mcp_servers", "deny_mcp_server_names"}:
                section = "deny_mcp_servers"
                policy.setdefault("deny_mcp_servers", [])
            elif section == "deny_mcp_risk_categories":
                policy.setdefault("deny_mcp_risk_categories", [])
            elif section == "require":
                policy.setdefault("require", {})
            else:
                section = None
            continue
        if section in {
            "deny_capabilities",
            "deny_mcp_servers",
            "deny_mcp_risk_categories",
        } and stripped.startswith("- "):
            value = stripped[2:].strip()
            if value:
                policy[section].append(value)  # type: ignore[index, union-attr]
            continue
        if section == "require" and ":" in stripped:
            key, value = stripped.split(":", 1)
            policy["require"][key.strip()] = _yaml_bool(value.strip())  # type: ignore[index]
            continue
        raise PolicyError(f"unsupported policy YAML line: {raw_line}")
    return policy


def normalize_capability(value: str) -> str | None:
    return CAPABILITY_ALIASES.get(value.strip().lower().replace(" ", "_"))


def normalize_mcp_risk_category(value: str) -> str | None:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "filesystem": "filesystem_access",
        "filesystem_access": "filesystem_access",
        "shell": "shell_process_execution",
        "process": "shell_process_execution",
        "shell_process": "shell_process_execution",
        "shell_process_execution": "shell_process_execution",
        "network": "browser_network_access",
        "browser": "browser_network_access",
        "browser_network": "browser_network_access",
        "browser_network_access": "browser_network_access",
        "database": "database_access",
        "database_access": "database_access",
        "cloud": "cloud_access",
        "cloud_access": "cloud_access",
        "secrets": "secrets_env_access",
        "env": "secrets_env_access",
        "secrets_env": "secrets_env_access",
        "secrets_env_access": "secrets_env_access",
        "unknown": "unknown_custom_server",
        "custom": "unknown_custom_server",
        "unknown_custom_server": "unknown_custom_server",
    }
    return aliases.get(normalized)


def _validate_severity(value: object, key: str, *, allow_none: bool = False) -> None:
    if value is None and allow_none:
        return
    if not isinstance(value, str) or value.lower() not in SEVERITY_ORDER:
        allowed = ", ".join(SEVERITY_ORDER)
        raise PolicyError(f"invalid severity for {key}: {value!r}; expected one of {allowed}")


def _string_list(value: object, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"policy value {key} must be a list of strings")
    strings = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"policy value {key} must be a list of strings")
        if item.strip():
            strings.append(item.strip())
    return strings


def _bool_value(value: object, key: str) -> bool:
    if isinstance(value, bool):
        return value
    raise PolicyError(f"policy value {key} must be true or false")


def _at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER[threshold.lower()]


def _normalize_name(value: str) -> str:
    return value.strip().lower()


def _normalize_reachable_capability(value: str) -> str | None:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "shell": "shell_execution",
        "shell_execution": "shell_execution",
        "code": "code_execution",
        "code_execution": "code_execution",
        "network": "network_access",
        "network_access": "network_access",
        "cloud": "cloud_access",
        "cloud_access": "cloud_access",
        "mcp": "mcp_tool_invocation",
        "mcp_tool_invocation": "mcp_tool_invocation",
        "autonomous_execution": "autonomous_execution",
    }
    return aliases.get(normalized)


def _finding_source(item: dict[str, Any]) -> str:
    for key in ("source_file", "path", "source"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dedupe_policy_items(items: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped = []
    seen = set()
    for item in items:
        key = (
            item.get("rule", ""),
            item.get("severity", ""),
            item.get("message", ""),
            item.get("source", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def has_human_approval_text(text: str) -> bool:
    return HUMAN_APPROVAL_RE.search(text) is not None


def _yaml_bool(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"true", "yes", "on", "required"}:
        return True
    if lowered in {"false", "no", "off", "optional"}:
        return False
    raise PolicyError(f"unsupported boolean value: {value}")


def _has_sandboxing_dependency(bom: dict[str, object]) -> bool:
    dependencies = bom.get("dependencies", [])
    if not isinstance(dependencies, list):
        return False
    return any(
        isinstance(item, dict) and item.get("category") == "sandbox_runtime"
        for item in dependencies
    )


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)
