from __future__ import annotations

from pathlib import Path

import pytest

from aigenguard.policy import PolicyError, load_toml_policy, parse_policy_yaml
from aigenguard.policy_onboarding import starter_policy_toml
from aigenguard.scanner import scan_path


ROOT = Path(__file__).resolve().parents[1]


def test_custom_policy_reports_denies_and_required_controls(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "model = 'gpt-4o'",
                "while True:",
                "    agent.run()",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "deny_capabilities:",
                "  - shell_execution",
                "  - autonomous_execution",
                "require:",
                "  sandboxing: true",
                "  human_approval: true",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    messages = {finding["message"] for finding in data["policy_findings"]}

    assert "custom policy violation: denied capability shell" in messages
    assert "custom policy violation: denied capability autonomous_execution" in messages
    assert "custom policy violation: sandboxing is required" in messages
    assert "custom policy violation: human approval is required" in messages


def test_custom_policy_required_controls_can_pass(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "SECURITY.md").write_text("Human approval required for tool use.\n", encoding="utf-8")
    (project / "requirements.txt").write_text("docker>=7\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "require:",
                "  sandboxing: true",
                "  human_approval: true",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)

    assert not any(
        finding["message"].startswith("custom policy violation")
        for finding in data["policy_findings"]
    )


def test_custom_policy_can_deny_mcp_servers_and_risk_categories(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "deny_mcp_servers:",
                "  - filesystem",
                "deny_mcp_risk_categories:",
                "  - filesystem_access",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    messages = {finding["message"] for finding in data["policy_findings"]}

    assert "custom policy violation: denied MCP server filesystem" in messages
    assert (
        "custom policy violation: denied MCP risk category filesystem_access"
        in messages
    )


def test_documented_policy_allows_high_risk_mcp_without_default_policy_gap(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "SECURITY.md").write_text(
        "Human approval required for filesystem MCP tools.\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["policy_findings"] == []


def test_policy_yaml_supports_deny_alias():
    policy = parse_policy_yaml(
        "\n".join(
            [
                "deny:",
                "  - shell",
                "require:",
                "  sandboxing: yes",
                "  human_approval: required",
            ]
        )
    )

    assert policy == {
        "deny_capabilities": ["shell"],
        "require": {"sandboxing": True, "human_approval": True},
    }


def test_toml_policy_denies_provider_model_framework_and_capability(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from crewai import Agent",
                "OPENROUTER_API_KEY = 'do-not-store'",
                "model = 'gpt-4o'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[providers]",
                'deny = ["openrouter"]',
                "[models]",
                'deny = ["gpt-4o"]',
                "[frameworks]",
                'deny = ["crewai"]',
                "[capabilities]",
                'deny = ["code_execution"]',
                "[mcp]",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    review = data["policy_review"]
    messages = {item["message"] for item in review["violations"]}

    assert review["mode"] == "advisory"
    assert "Provider denied by policy: openrouter." in messages
    assert "Model denied by policy: gpt-4o." in messages
    assert "Framework denied by policy: crewai." in messages
    assert "Denied reachable capability detected: code_execution." in messages


def test_toml_policy_allow_list_flags_values_outside_allow_list(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from openai import OpenAI",
                "OPENROUTER_API_KEY = 'do-not-store'",
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[providers]",
                'allow = ["openai"]',
                "[mcp]",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    messages = {item["message"] for item in data["policy_review"]["violations"]}

    assert "Provider not allowed by policy: openrouter." in messages


def test_toml_policy_secret_warning_does_not_include_secret_value(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "OPENAI_API_KEY = 'do-not-store'\n",
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[secrets]",
                "warn_on_detected = true",
                "[mcp]",
                "require_policy_for_risky_servers = false",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    review_text = str(data["policy_review"])

    assert "Secret reference detected and secrets.warn_on_detected is enabled." in review_text
    assert "do-not-store" not in review_text


def test_toml_policy_mcp_unknown_and_risky_server_rules(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "custom-local": {"command": "custom-local"},
            "shell-runner": {"command": "bash"}
          }
        }
        """,
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[mcp]",
                "warn_on_unknown_server = true",
                "require_policy_for_risky_servers = true",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    warning_messages = {item["message"] for item in data["policy_review"]["warnings"]}
    violation_messages = {item["message"] for item in data["policy_review"]["violations"]}

    assert "Unknown MCP server detected: custom-local." in warning_messages
    assert "Risky MCP server lacks policy evidence: shell-runner." in violation_messages


def test_toml_policy_gap_and_repository_risk_thresholds(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("system prompt\n", encoding="utf-8")
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[risk]",
                'warn_on = "low"',
                "[policy_gaps]",
                'warn_on = "low"',
                "[mcp]",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    violation_messages = {item["message"] for item in data["policy_review"]["violations"]}
    warning_messages = {item["message"] for item in data["policy_review"]["warnings"]}

    assert "Repository risk is low, policy warns on low or above." in violation_messages
    assert "Policy gap detected at or above threshold." in warning_messages


def test_toml_policy_invalid_severity_is_clear(tmp_path):
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[risk]\nwarn_on = \"urgent\"\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="invalid severity for risk.warn_on"):
        load_toml_policy(policy)


def test_strict_example_blocks_secret_leaks_like_builtin_strict_preset(tmp_path):
    builtin_path = tmp_path / "strict.toml"
    builtin_path.write_text(starter_policy_toml(preset="strict"), encoding="utf-8")

    example = load_toml_policy(ROOT / "examples" / "policies" / "strict-aigenguard.toml")
    builtin = load_toml_policy(builtin_path)

    assert example["secrets"] == builtin["secrets"]
    assert example["secrets"]["block_leaks"] is True
