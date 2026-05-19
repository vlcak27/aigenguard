"""Policy onboarding helpers for AgentBOM."""

from __future__ import annotations

from pathlib import Path
from typing import Any


ADVISORY_POLICY_TOML = """# Advisory AgentBOM policy for first reviews.
# Run without --enforce-policy until the generated report matches expectations.

[risk]
warn_on = "high"

[providers]
# Empty allow lists mean "do not restrict by allow list".
allow = []
deny = []

[models]
allow = []
deny = []

[frameworks]
allow = []
deny = []

[capabilities]
# Start by reviewing sensitive reachable capabilities in the report.
deny = []

[mcp]
allow_servers = []
deny_servers = []
warn_on_unknown_server = true
require_policy_for_risky_servers = false

[secrets]
warn_on_detected = true

[policy_gaps]
warn_on = "medium"
"""


STRICT_POLICY_TOML = """# Stricter AgentBOM policy.
# Test this without --enforce-policy first:
# agentbom scan . --policy agentbom.toml --pretty

[risk]
warn_on = "high"

[providers]
allow = []
deny = [
  "openrouter",
]

[models]
allow = []
deny = []

[frameworks]
allow = []
deny = []

[capabilities]
deny = [
  "shell_execution",
  "code_execution",
  "network_access",
]

[mcp]
allow_servers = []
deny_servers = []
warn_on_unknown_server = true
require_policy_for_risky_servers = true

[secrets]
warn_on_detected = true

[policy_gaps]
warn_on = "medium"
"""


def starter_policy_toml(*, strict: bool = False) -> str:
    """Return the built-in starter policy template."""
    return STRICT_POLICY_TOML if strict else ADVISORY_POLICY_TOML


def suggested_policy_toml(bom: dict[str, Any]) -> str:
    """Build a useful advisory policy from current scan findings."""
    denied_capabilities = _high_risk_reachable_capabilities(bom.get("reachable_capabilities"))
    capability_comment = (
        "# High-risk reachable capabilities detected in this scan."
        if denied_capabilities
        else "# Add deny entries after review, if needed."
    )
    return "\n".join(
        [
            "# Suggested AgentBOM policy from current scan findings.",
            "# Review this in advisory mode before using --enforce-policy.",
            "",
            "[risk]",
            'warn_on = "high"',
            "",
            "[providers]",
            "# Empty allow lists avoid surprising failures while you review.",
            "allow = []",
            "deny = []",
            "",
            "[models]",
            "allow = []",
            "deny = []",
            "",
            "[frameworks]",
            "allow = []",
            "deny = []",
            "",
            "[capabilities]",
            capability_comment,
            f"deny = {_toml_array(denied_capabilities)}",
            "",
            "[mcp]",
            "allow_servers = []",
            "deny_servers = []",
            "warn_on_unknown_server = true",
            "require_policy_for_risky_servers = true",
            "",
            "[secrets]",
            "warn_on_detected = true",
            "",
            "[policy_gaps]",
            'warn_on = "medium"',
            "",
        ]
    )


def write_policy_file(path: str | Path, text: str, *, force: bool = False) -> Path:
    """Write a policy file without overwriting unless requested."""
    policy_path = Path(path)
    if policy_path.exists() and not force:
        raise FileExistsError(str(policy_path))
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(text.rstrip() + "\n", encoding="utf-8")
    return policy_path


def next_steps(policy_path: str | Path) -> list[str]:
    policy = Path(policy_path).as_posix()
    return [
        f"agentbom scan . --policy {policy} --pretty",
        f"agentbom scan . --policy {policy} --html --open",
        f"agentbom scan . --policy {policy} --enforce-policy",
    ]


def _high_risk_reachable_capabilities(items: object) -> list[str]:
    values = []
    seen = set()
    if not isinstance(items, list):
        return values
    for item in items:
        if not isinstance(item, dict) or item.get("risk") != "high":
            continue
        value = str(item.get("capability", "")).strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return sorted(values)


def _toml_array(values: list[str]) -> str:
    if not values:
        return "[]"
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
