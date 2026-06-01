from __future__ import annotations

import json
from pathlib import Path

from aigenguard.cli import main
from aigenguard.scanner import scan_path


ROOT = Path(__file__).resolve().parents[1]
SAFE_DEMO = ROOT / "examples" / "mcp-safe-agent"
RISKY_DEMO = ROOT / "examples" / "mcp-risky-agent"
MCP_POLICY = ROOT / "examples" / "policies" / "mcp-policy.yaml"


def test_mcp_safe_agent_scans_with_controlled_mcp_findings():
    data = scan_path(SAFE_DEMO)

    assert data["repository_risk"]["severity"] in {"low", "medium"}
    assert data["policy_findings"] == []
    assert {
        "name": "approved-memory",
        "path": ".mcp.json",
        "confidence": "medium",
        "kind": "server",
        "parse_status": "parsed",
        "risk": "low",
        "risk_categories": ["unknown_custom_server"],
        "rationale": ["custom or unknown MCP server: @modelcontextprotocol/server-memory"],
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-memory"],
        "transport": "stdio",
        "package": "@modelcontextprotocol/server-memory",
    } in data["mcp_servers"]
    assert any(
        item.get("capability") == "mcp_tool_invocation"
        and item.get("mcp_server") == "approved-memory"
        for item in data["reachable_capabilities"]
    )


def test_mcp_risky_agent_scans_with_expected_risky_categories():
    data = scan_path(RISKY_DEMO)

    categories = {
        category
        for server in data["mcp_servers"]
        for category in server.get("risk_categories", [])
    }

    assert data["repository_risk"]["severity"] in {"high", "critical"}
    assert {
        "filesystem_access",
        "shell_process_execution",
        "browser_network_access",
        "database_access",
        "cloud_access",
        "secrets_env_access",
    } <= categories
    assert "BRAVE_SEARCH_API_KEY" in json.dumps(data)
    assert "DATABASE_URL" in json.dumps(data)
    assert "${BRAVE_SEARCH_API_KEY}" not in json.dumps(data)
    assert "${DATABASE_URL}" not in json.dumps(data)
    assert any(
        item.get("capability") == "mcp_tool_invocation"
        and item.get("reachable_from") == "langgraph"
        for item in data["reachable_capabilities"]
    )


def test_mcp_policy_example_reports_expected_denies():
    data = scan_path(RISKY_DEMO, policy_path=MCP_POLICY)
    messages = {finding["message"] for finding in data["policy_findings"]}

    assert "custom policy violation: denied MCP server shell-runner" in messages
    assert "custom policy violation: denied MCP server cloud-admin" in messages
    assert (
        "custom policy violation: denied MCP risk category filesystem_access"
        in messages
    )
    assert (
        "custom policy violation: denied MCP risk category shell_process_execution"
        in messages
    )
    assert (
        "custom policy violation: denied MCP risk category secrets_env_access"
        in messages
    )
    assert "custom policy violation: human approval is required" in messages


def test_mcp_demo_report_generation_outputs_json_html_mermaid_and_sarif(tmp_path):
    output_dir = tmp_path / "mcp-risky-report"

    result = main(
        [
            "scan",
            str(RISKY_DEMO),
            "--output-dir",
            str(output_dir),
            "--html",
            "--mermaid",
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    json_path = output_dir / "agentbom.json"
    html_path = output_dir / "agentbom.html"
    mermaid_path = output_dir / "agentbom.mmd"
    sarif_path = output_dir / "agentbom.sarif"
    assert json_path.exists()
    assert html_path.exists()
    assert mermaid_path.exists()
    assert sarif_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    mermaid = mermaid_path.read_text(encoding="utf-8")
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))

    assert "MCP Security Analysis" in html
    assert "filesystem_access" in html
    assert "MCP Server: filesystem" in mermaid
    assert "MCP Risk: shell_process_execution" in mermaid
    assert any(server["name"] == "filesystem" for server in data["mcp_servers"])
    assert sarif["version"] == "2.1.0"
    assert all(
        result.get("locations")
        for result in sarif["runs"][0]["results"]
    )
