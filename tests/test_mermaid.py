from __future__ import annotations

from aigenguard.cli import main
from aigenguard.mermaid import render_mermaid


def test_cli_generates_mermaid_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--mermaid"])

    assert result == 0
    mermaid_path = output_dir / "agentbom.mmd"
    assert mermaid_path.exists()

    mermaid = mermaid_path.read_text(encoding="utf-8")

    assert mermaid.startswith("flowchart TD\n")
    assert "Model: gpt-4o" in mermaid
    assert "Framework: langchain" in mermaid
    assert "Reachable: gpt-4o -&gt; code_execution" in mermaid
    assert " -- reaches --> " in mermaid
    assert "classDef high" in mermaid


def test_mermaid_graph_contains_attack_surface_relationships():
    mermaid = render_mermaid(_sample_bom())

    assert "Provider: openai" in mermaid
    assert "Model: gpt-4o" in mermaid
    assert "Framework: langchain" in mermaid
    assert "MCP Server: filesystem" in mermaid
    assert "MCP Risk: filesystem_access" in mermaid
    assert "Capability: code_execution" in mermaid
    assert "Reachable: langchain -&gt; code_execution" in mermaid
    assert "Policy: shell execution detected without restrictions" in mermaid
    assert " -- uses --> " in mermaid
    assert " -- enables --> " in mermaid
    assert " -- reaches --> " in mermaid
    assert " -- exposes --> " in mermaid
    assert " -- risk --> " in mermaid
    assert " -- policy --> " in mermaid
    assert "classDef low" in mermaid
    assert "classDef medium" in mermaid
    assert "classDef high" in mermaid
    assert "classDef critical" in mermaid


def test_mermaid_escapes_labels():
    mermaid = render_mermaid(
        {
            "providers": [
                {
                    "name": 'openai "prod"',
                    "path": "agent.py",
                    "confidence": "high",
                }
            ],
            "models": [
                {
                    "type": "model",
                    "name": "gpt-4o<script>",
                    "source_file": "agent.py",
                    "confidence": "high",
                    "evidence": "gpt-4o<script>",
                }
            ],
            "frameworks": [],
            "capabilities": [],
            "reachable_capabilities": [],
            "policy_findings": [
                {
                    "severity": "critical",
                    "message": 'review "prompt" <input>',
                    "source_file": "AGENTS.md",
                }
            ],
        }
    )

    assert "&quot;prod&quot;" in mermaid
    assert "gpt-4o&lt;script&gt;" in mermaid
    assert "review &quot;prompt&quot; &lt;input&gt;" in mermaid
    assert '"prod"' not in mermaid
    assert "<script>" not in mermaid


def test_mermaid_output_is_deterministic():
    bom = _sample_bom()
    reordered = {
        **bom,
        "providers": list(reversed(bom["providers"])),
        "models": list(reversed(bom["models"])),
        "frameworks": list(reversed(bom["frameworks"])),
        "capabilities": list(reversed(bom["capabilities"])),
        "reachable_capabilities": list(reversed(bom["reachable_capabilities"])),
        "policy_findings": list(reversed(bom["policy_findings"])),
    }

    assert render_mermaid(bom) == render_mermaid(reordered)


def _sample_bom():
    return {
        "providers": [
            {"name": "openai", "path": "agent.py", "confidence": "high"},
        ],
        "models": [
            {
                "type": "model",
                "name": "gpt-4o",
                "source_file": "agent.py",
                "confidence": "high",
                "evidence": "gpt-4o",
            },
        ],
        "frameworks": [
            {"name": "langchain", "path": "agent.py", "confidence": "high"},
        ],
        "mcp_servers": [
            {
                "name": "filesystem",
                "path": "mcp.json",
                "confidence": "medium",
                "kind": "server",
                "parse_status": "parsed",
                "risk": "high",
                "risk_categories": ["filesystem_access"],
                "rationale": ["server name or package suggests filesystem access"],
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "package": "@modelcontextprotocol/server-filesystem",
                "transport": "stdio",
            },
        ],
        "capabilities": [
            {"name": "shell", "path": "agent.py", "confidence": "high"},
        ],
        "reachable_capabilities": [
            {
                "capability": "code_execution",
                "reachable_from": "langchain",
                "source_file": "agent.py",
                "risk": "high",
                "confidence": "high",
                "confidence_score": 100,
                "paths": ["shell_execution"],
            },
        ],
        "policy_findings": [
            {
                "severity": "high",
                "message": "shell execution detected without restrictions",
                "source_file": "agent.py",
            },
        ],
    }
