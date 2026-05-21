from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentbom.cli import main
from agentbom.github_summary import render_github_step_summary, write_github_step_summary
from agentbom.html_report import _table, render_html


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert "agentbom 0.8.0" in capsys.readouterr().out


def test_cli_help_mentions_core_workflows(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "offline" in help_text
    assert "--html" in help_text
    assert "--mermaid" in help_text
    assert "--sarif" in help_text
    assert "--policy" in help_text
    assert "--enforce-policy" in help_text
    assert "--suggest-policy" in help_text
    assert "--open" in help_text
    assert "opens the generated HTML report" in help_text
    assert "--baseline" in help_text
    assert "--fail-on-new" in help_text
    assert "JSON and Markdown reports are always written" in help_text
    assert "optional reports" in help_text
    assert "diff and policy gates" in help_text
    assert "Common workflows" in help_text
    assert "Policy review is advisory by default" in help_text
    assert "Add --enforce-policy only after review" in help_text


def test_cli_top_level_help_mentions_init(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "init" in help_text
    assert "activate" in help_text
    assert "status" in help_text
    assert "deactivate" in help_text
    assert "Recommended workflow" in help_text
    assert "agentbom activate" in help_text
    assert "git commit" in help_text
    assert "agentbom status" in help_text
    assert "agentbom scan . --policy agentbom.toml --html --open" in help_text


def test_cli_fail_on_new_error_mentions_required_baseline(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", ".", "--fail-on-new", "high"])

    assert exc.value.code == 2
    assert "--fail-on-new requires --baseline PATH" in capsys.readouterr().err


def test_cli_generates_json_and_markdown(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()

    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "OPENAI_API_KEY = 'do-not-store'",
            ]
        ),
        encoding="utf-8",
    )

    (project / "mcp.json").write_text(
        "{}",
        encoding="utf-8",
    )

    (project / "AGENTS.md").write_text(
        "prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert not (output_dir / "agentbom.html").exists()
    assert not (output_dir / "agentbom.sarif").exists()

    data = json.loads(
        (output_dir / "agentbom.json").read_text(encoding="utf-8")
    )

    markdown = (output_dir / "agentbom.md").read_text(
        encoding="utf-8"
    )

    assert "capability_graph" in data
    assert "policy_review" not in data
    assert "Capability Graph" not in markdown
    assert "Policy review" not in markdown

    assert {
        "name": "openai",
        "path": "agent.py",
        "confidence": "high",
    } in data["providers"]

    assert {
        "name": "langchain",
        "path": "agent.py",
        "confidence": "high",
    } in data["frameworks"]

    assert data["mcp_servers"] == [
        {
            "name": "mcp.json",
            "path": "mcp.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "no_servers",
        }
    ]

    assert {
        "path": "AGENTS.md",
        "type": "prompt",
        "confidence": "low",
    } in data["prompts"]

    assert {
        "name": "shell",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]

    assert any(
        item["name"] == "OPENAI_API_KEY"
        for item in data["secret_references"]
    )

    assert not any(
        item["name"] == "api_key"
        for item in data["secret_references"]
    )

    assert not any(
        item["name"] == "openai_api_key"
        for item in data["secret_references"]
    )

    assert "do-not-store" not in json.dumps(data)


def test_cli_scan_prints_report_path_and_no_policy_next_steps(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"

    result = main(["scan", str(project), "--output-dir", str(output_dir)])

    assert result == 0
    captured = capsys.readouterr()
    assert f"Reports written to: {output_dir.as_posix()}/" in captured.out
    assert "Next:" in captured.out
    assert "Open HTML report:" in captured.out
    assert "Start policy review:" in captured.out
    assert "agentbom init" in captured.out
    assert "--enforce-policy" not in captured.out


def test_cli_scan_html_prints_html_report_path(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--html"])

    assert result == 0
    captured = capsys.readouterr()
    assert "HTML report:" in captured.out
    assert f"{output_dir.as_posix()}/agentbom.html" in captured.out
    assert "Open it:" in captured.out
    assert "--html --open" in captured.out


def test_cli_scan_open_success_avoids_redundant_open_instruction(
    tmp_path, monkeypatch, capsys
):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"
    monkeypatch.setattr("agentbom.cli.webbrowser.open", lambda url: True)

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--html", "--open"])

    assert result == 0
    captured = capsys.readouterr()
    assert "Opened HTML report:" in captured.out
    assert "Open it:" not in captured.out


def test_cli_next_step_output_does_not_print_secret_values(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "OPENAI_API_KEY = 'do-not-store'\n",
        encoding="utf-8",
    )

    result = main(["scan", str(project), "--output-dir", str(tmp_path / "out")])

    assert result == 0
    assert "do-not-store" not in capsys.readouterr().out


def test_cli_init_writes_starter_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = main(["init"])

    assert result == 0
    policy = tmp_path / "agentbom.toml"
    text = policy.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert policy.exists()
    assert "[risk]" in text
    assert 'warn_on = "high"' in text
    assert "require_policy_for_risky_servers = false" in text
    assert "Created agentbom.toml" in captured.out
    assert "agentbom scan . --policy agentbom.toml --pretty" in captured.out
    assert "agentbom scan . --policy agentbom.toml --html --open" in captured.out
    assert "agentbom scan . --policy agentbom.toml --enforce-policy" in captured.out


def test_cli_init_does_not_overwrite_existing_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    policy = tmp_path / "agentbom.toml"
    policy.write_text("existing\n", encoding="utf-8")

    result = main(["init"])

    assert result == 1
    assert policy.read_text(encoding="utf-8") == "existing\n"
    captured = capsys.readouterr()
    assert "policy file already exists" in captured.err
    assert "--force" in captured.err
    assert "--output PATH" in captured.err


def test_cli_init_force_overwrites_existing_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    policy = tmp_path / "agentbom.toml"
    policy.write_text("existing\n", encoding="utf-8")

    result = main(["init", "--force"])

    assert result == 0
    assert "[risk]" in policy.read_text(encoding="utf-8")


def test_cli_init_strict_writes_stricter_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = main(["init", "--strict"])

    assert result == 0
    text = (tmp_path / "agentbom.toml").read_text(encoding="utf-8")
    assert '"shell_execution"' in text
    assert '"code_execution"' in text
    assert "require_policy_for_risky_servers = true" in text
    assert "Run advisory mode before enforcement" in capsys.readouterr().out


def test_cli_init_output_custom_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = main(["init", "--output", "policies/agentbom.toml"])

    assert result == 0
    assert (tmp_path / "policies" / "agentbom.toml").exists()
    assert not (tmp_path / "agentbom.toml").exists()


def test_cli_suggest_policy_writes_policy_and_scan_outputs(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    policy = tmp_path / "agentbom.toml"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--suggest-policy",
            str(policy),
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    text = policy.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert 'warn_on = "high"' in text
    assert "warn_on_detected = true" in text
    assert "warn_on_unknown_server = true" in text
    assert "require_policy_for_risky_servers = true" in text
    assert '"code_execution"' in text
    assert "do-not-store" not in text
    assert "Suggested policy written to" in captured.out
    assert f"agentbom scan . --policy {policy.as_posix()} --pretty" in captured.out
    assert f"agentbom scan . --policy {policy.as_posix()} --html --open" in captured.out


def test_cli_suggest_policy_does_not_overwrite_without_force(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    policy = tmp_path / "agentbom.toml"
    policy.write_text("existing\n", encoding="utf-8")

    result = main(["scan", str(project), "--suggest-policy", str(policy)])

    assert result == 1
    assert policy.read_text(encoding="utf-8") == "existing\n"
    captured = capsys.readouterr()
    assert "policy file already exists" in captured.err
    assert "--force" in captured.err


def test_cli_suggest_policy_force_overwrites_existing_file(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    policy = tmp_path / "agentbom.toml"
    policy.write_text("existing\n", encoding="utf-8")

    result = main(["scan", str(project), "--suggest-policy", str(policy), "--force"])

    assert result == 0
    assert "[risk]" in policy.read_text(encoding="utf-8")


def test_cli_scan_html_open_calls_webbrowser(tmp_path, monkeypatch, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"
    opened = []
    monkeypatch.setattr("agentbom.cli.webbrowser.open", lambda url: opened.append(url) or True)

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--html", "--open"])

    assert result == 0
    assert (output_dir / "agentbom.html").exists()
    assert opened == [(output_dir / "agentbom.html").resolve().as_uri()]
    assert "HTML report:" in capsys.readouterr().out


def test_cli_scan_open_without_html_generates_html(tmp_path, monkeypatch):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"
    opened = []
    monkeypatch.setattr("agentbom.cli.webbrowser.open", lambda url: opened.append(url) or True)

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--open"])

    assert result == 0
    assert (output_dir / "agentbom.html").exists()
    assert opened


def test_cli_scan_open_failure_does_not_fail_scan(tmp_path, monkeypatch, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"

    def fail_open(url):
        raise RuntimeError(f"cannot open {url}")

    monkeypatch.setattr("agentbom.cli.webbrowser.open", fail_open)

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--html", "--open"])

    assert result == 0
    assert (output_dir / "agentbom.html").exists()
    captured = capsys.readouterr()
    assert "HTML report:" in captured.out
    assert "Could not open browser automatically" in captured.err


def test_cli_scan_without_open_does_not_call_webbrowser(tmp_path, monkeypatch):
    project = tmp_path / "agent"
    project.mkdir()
    output_dir = tmp_path / "out"

    def unexpected_open(url):
        raise AssertionError(f"unexpected browser open: {url}")

    monkeypatch.setattr("agentbom.cli.webbrowser.open", unexpected_open)

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--html"])

    assert result == 0
    assert (output_dir / "agentbom.html").exists()


def test_cli_writes_github_step_summary_when_env_is_set(tmp_path, monkeypatch):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {"command": "npx", "args": ["-y", "@mcp/filesystem"]},
            "browser": {"command": "npx", "args": ["-y", "@mcp/browser"]}
          }
        }
        """,
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--html",
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    summary = summary_path.read_text(encoding="utf-8")
    assert "# AgentBOM scan summary" in summary
    assert "Risk:" in summary
    assert "- Providers: openai" in summary
    assert "- Models: gpt-4o" in summary
    assert "- Frameworks: langchain" in summary
    assert "- MCP servers: 2 (browser, filesystem)" in summary
    assert "## Reachable capabilities" in summary
    assert "| Capability | Reachable from | Risk | Source |" in summary
    assert "- agentbom.json" in summary
    assert "- agentbom.md" in summary
    assert "- agentbom.html" in summary
    assert "- agentbom.sarif" in summary
    assert "do-not-store" not in summary


def test_github_step_summary_is_not_written_when_env_is_absent(tmp_path):
    summary_path = tmp_path / "summary.md"

    wrote = write_github_step_summary(
        {"repository_risk": {"severity": "low", "score": 0}},
        [tmp_path / "agentbom.json"],
        environ={},
    )

    assert wrote is False
    assert not summary_path.exists()


def test_github_step_summary_failure_does_not_fail_scan(tmp_path, monkeypatch):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path))

    result = main(["scan", str(project), "--output-dir", str(output_dir)])

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()


def test_github_step_summary_escapes_untrusted_markdown_values():
    summary = render_github_step_summary(
        {
            "repository_risk": {"severity": "high", "score": 70},
            "providers": [
                {"name": "<script>alert(1)</script>", "path": "agent.py"}
            ],
            "models": [{"name": "gpt|evil\nnext", "source_file": "agent.py"}],
            "frameworks": [{"name": "**langgraph**", "path": "agent.py"}],
            "mcp_servers": [{"name": "filesystem|prod", "path": "mcp.json"}],
            "reachable_capabilities": [
                {
                    "capability": "shell|execution",
                    "reachable_from": "<langgraph>",
                    "risk": "high",
                    "source_file": "agent|prod.py",
                }
            ],
        },
        [Path("agentbom.json")],
    )

    assert "<script>" not in summary
    assert "&lt;script&gt;alert\\(1\\)&lt;/script&gt;" in summary
    assert "\\*\\*langgraph\\*\\*" in summary
    assert "gpt|evil next" in summary
    assert "shell\\|execution" in summary
    assert "agent\\|prod.py" in summary
    assert "agentbom.json" in summary


def test_cli_generates_html_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()

    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    (project / "AGENTS.md").write_text(
        "system prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--html",
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert (output_dir / "agentbom.html").exists()

    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")

    assert "<style>" in html
    assert "<script src" not in html.lower()
    assert "<link" not in html.lower()
    assert "AgentBOM Security Report" in html
    assert "Overview" in html
    assert "Review workflow" in html
    assert "Review Priorities" in html
    assert "How to read this report" in html
    assert "Use Policy Workbench to generate a starter agentbom.toml." in html
    assert "Providers &amp; Models" in html
    assert "MCP Security Analysis" in html
    assert "Reachable Capabilities" in html
    assert "Policy Findings" in html
    assert "Prompt Files" in html
    assert "Policy Workbench" in html
    assert "Generate a starter agentbom.toml from current findings" in html
    assert "Run the policy in advisory mode first" in html
    assert "Copy policy" in html
    assert "Download agentbom.toml" in html
    assert "agentbom scan . --policy agentbom.toml --html --open" in html
    assert "agentbom scan . --policy agentbom.toml --pretty" in html
    assert "Local guard" in html
    assert "agentbom install-hook --policy agentbom.toml --mode advisory" in html
    assert "agentbom install-hook --policy agentbom.toml --mode confirm" in html
    assert "agentbom install-hook --policy agentbom.toml --mode enforce" in html
    assert "Capability Graph" in html
    assert "score-ring" in html
    assert "severity-" in html
    assert "do-not-store" not in html


def test_html_report_escapes_bom_values():
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "<unsafe>",
            "generated_by": "agentbom",
            "providers": [
                {"name": "<openai>", "path": "agent.py", "confidence": "high"}
            ],
            "models": [],
            "frameworks": [],
            "mcp_servers": [
                {
                    "name": "<filesystem>",
                    "path": "mcp.json",
                    "confidence": "medium",
                    "kind": "server",
                    "parse_status": "parsed",
                    "risk": "high",
                    "risk_categories": ["filesystem_access"],
                    "rationale": ["review <filesystem> access"],
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "package": "@modelcontextprotocol/server-filesystem",
                    "transport": "stdio",
                }
            ],
            "capabilities": [],
            "dependencies": [],
            "reachable_capabilities": [],
            "capability_graph": {"nodes": [], "edges": []},
            "policy_findings": [],
            "repository_risk": {
                "score": 0,
                "severity": "low",
                "rationale": ["review <prompt> handling"],
            },
            "secret_references": [],
            "risks": [],
        }
    )

    assert "&lt;unsafe&gt;" in html
    assert "&lt;openai&gt;" in html
    assert "&lt;filesystem&gt;" in html
    assert "@modelcontextprotocol/server-filesystem" in html
    assert "review &lt;prompt&gt; handling" in html
    assert "review &lt;filesystem&gt; access" in html
    assert "<unsafe>" not in html
    assert "\\u003copenai\\u003e" in html


def test_html_report_table_escapes_cells_by_default():
    html = _table(["Name"], [["<img src=x onerror=alert(1)>"]], "None.")

    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_report_escapes_xss_payloads_in_report_fields():
    image_payload = "<img src=x onerror=alert(1)>"
    script_payload = "<script>alert(1)</script>"
    svg_payload = '"><svg onload=alert(1)>'
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "repo",
            "generated_by": "agentbom",
            "providers": [
                {"name": image_payload, "path": svg_payload, "confidence": "high"}
            ],
            "models": [
                {
                    "name": script_payload,
                    "type": "llm",
                    "source_file": svg_payload,
                    "confidence": "high",
                    "evidence": image_payload,
                }
            ],
            "frameworks": [],
            "mcp_servers": [
                {
                    "name": svg_payload,
                    "path": "mcp.json",
                    "kind": "server",
                    "parse_status": "parsed",
                    "risk": "high",
                    "risk_categories": ["network"],
                    "rationale": [script_payload],
                    "command": "npx",
                    "args": [script_payload],
                    "package": image_payload,
                    "transport": "stdio",
                }
            ],
            "capabilities": [],
            "dependencies": [
                {
                    "name": image_payload,
                    "category": "ai",
                    "path": svg_payload,
                    "confidence": "high",
                }
            ],
            "reachable_capabilities": [
                {
                    "capability": "filesystem",
                    "reachable_from": "agent",
                    "source_file": svg_payload,
                    "risk": "high",
                    "confidence": "high",
                    "paths": [script_payload],
                    "mcp_server": svg_payload,
                    "rationale": [image_payload],
                }
            ],
            "capability_graph": {
                "nodes": [{"id": "agent", "type": "actor", "name": script_payload}],
                "edges": [{"source": "agent", "target": svg_payload, "type": "uses"}],
            },
            "policy_findings": [
                {
                    "severity": "high",
                    "message": script_payload,
                    "source_file": svg_payload,
                    "policy_id": "xss",
                }
            ],
            "secret_references": [],
            "risks": [{"severity": "high", "reason": image_payload}],
            "repository_risk": {
                "score": 80,
                "severity": "high",
                "rationale": [script_payload],
            },
        }
    )

    assert image_payload not in html
    assert script_payload not in html
    assert svg_payload not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&quot;&gt;&lt;svg onload=alert(1)&gt;" in html
    assert html.count("<script>") == 1
    assert "<script>alert(1)</script>" not in html


def test_cli_generates_sarif_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()

    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "model = 'gpt-4o'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    (project / "AGENTS.md").write_text(
        "prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert (output_dir / "agentbom.sarif").exists()

    sarif = json.loads(
        (output_dir / "agentbom.sarif").read_text(encoding="utf-8")
    )

    run = sarif["runs"][0]
    results = run["results"]

    rule_ids = {
        result["ruleId"]
        for result in results
    }

    rules = run["tool"]["driver"]["rules"]

    rules_by_id = {
        rule["id"]: rule
        for rule in rules
    }

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AgentBOM"
    assert run["tool"]["driver"]["semanticVersion"] == "0.8.0"

    assert "risk.high" in rule_ids
    assert "risk.low" in rule_ids
    assert "reachable.code_execution" in rule_ids
    assert "policy.prompt_file_detected_without_security_policy" in rule_ids
    assert "policy.shell_execution_detected_without_restrictions" in rule_ids

    assert rules_by_id["reachable.code_execution"]["shortDescription"]["text"]

    assert (
        "Remediation:"
        in rules_by_id["reachable.code_execution"]["help"]["text"]
    )

    assert (
        rules_by_id["reachable.code_execution"]["defaultConfiguration"]["level"]
        == "error"
    )

    assert (
        rules_by_id["reachable.code_execution"]["properties"]["security-severity"]
        == "8.0"
    )

    assert all(
        result["ruleIndex"]
        == rules.index(rules_by_id[result["ruleId"]])
        for result in results
    )

    assert len(rule_ids) == len(results)

    locations = [
        location
        for result in results
        for location in result.get("locations", [])
    ]

    assert {
        "physicalLocation": {
            "artifactLocation": {
                "uri": "agent.py",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": 1,
            },
        }
    } in locations
    assert all(
        result.get("locations")
        and all(
            location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            for location in result["locations"]
        )
        for result in results
    )


def test_sarif_emits_high_risk_mcp_server_findings(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "shell-runner": {
              "command": "python",
              "args": ["-m", "local_shell_server"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))
    rule_ids = {result["ruleId"] for result in sarif["runs"][0]["results"]}

    assert "mcp.high_risk_server.shell_runner" in rule_ids


def test_cli_generates_diff_outputs_and_fails_on_new_threshold(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "repository": "baseline",
                "providers": [],
                "capabilities": [],
                "secret_references": [],
                "policy_findings": [],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "high",
            "--html",
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 1
    captured = capsys.readouterr()
    assert "New findings at or above high severity were introduced." in captured.err

    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")
    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")
    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))

    introduced = {
        (item["category"], item["title"], item["severity"])
        for item in data["diff"]["introduced"]
    }
    assert ("providers", "openai", "low") in introduced
    assert ("capabilities", "shell", "high") in introduced
    assert ("secret_references", "OPENAI_API_KEY", "high") in introduced
    assert "Changes since baseline" in markdown
    assert "| Introduced |" in markdown
    assert "Introduced Findings" in markdown
    assert "diff" in html
    assert "Changes since baseline" in html
    assert "Introduced Findings" in html
    assert any(
        result["ruleId"].startswith("diff.introduced.capabilities.")
        for result in sarif["runs"][0]["results"]
    )


def test_cli_fail_on_new_allows_lower_severity_introductions(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "repository": "baseline",
                "providers": [],
                "capabilities": [],
                "secret_references": [],
                "policy_findings": [],
            }
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(tmp_path / "out"),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "medium",
        ]
    )

    assert result == 0


def test_cli_policy_is_advisory_by_default(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(["from openai import OpenAI", "model = 'gpt-4o'"]),
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[models]\ndeny = [\"gpt-4o\"]\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = main(["scan", str(project), "--output-dir", str(output_dir), "--policy", str(policy)])

    assert result == 0
    captured = capsys.readouterr()
    assert "Policy review: failed" in captured.out
    assert "Mode: advisory" in captured.out
    assert "Model denied by policy: gpt-4o." in captured.out
    assert "Policy violations do not fail the scan unless --enforce-policy is used." in captured.out
    assert "Review policy findings in the report." in captured.out
    assert "Update" in captured.out
    assert "Enforce after review:" in captured.out
    assert "--enforce-policy" in captured.out
    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    assert data["policy_review"]["mode"] == "advisory"


def test_cli_enforce_policy_exits_nonzero_for_violations(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("model = 'gpt-4o'\n", encoding="utf-8")
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[models]\ndeny = [\"gpt-4o\"]\n", encoding="utf-8")

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(tmp_path / "out"),
            "--policy",
            str(policy),
            "--enforce-policy",
        ]
    )

    assert result == 1
    captured = capsys.readouterr()
    assert "Mode: enforced" in captured.out
    assert "Policy enforcement failed. Fix policy violations before committing/merging." in captured.out


def test_cli_policy_pass_exits_zero(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[risk]",
                'warn_on = "critical"',
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(tmp_path / "out"),
            "--policy",
            str(policy),
            "--enforce-policy",
        ]
    )

    assert result == 0
    captured = capsys.readouterr()
    assert "Policy review: passed" in captured.out
    assert "Policy enforcement passed." in captured.out


def test_cli_invalid_policy_toml_exits_nonzero_with_clear_error(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[risk\n", encoding="utf-8")

    result = main(["scan", str(project), "--output-dir", str(tmp_path / "out"), "--policy", str(policy)])

    assert result == 1
    assert "invalid policy TOML" in capsys.readouterr().err


def test_cli_invalid_policy_severity_exits_nonzero_with_clear_error(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[risk]\nwarn_on = \"urgent\"\n", encoding="utf-8")

    result = main(["scan", str(project), "--output-dir", str(tmp_path / "out"), "--policy", str(policy)])

    assert result == 1
    assert "invalid severity for risk.warn_on" in capsys.readouterr().err


def test_cli_missing_policy_file_exits_nonzero_with_clear_error(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    policy = tmp_path / "missing.toml"

    result = main(["scan", str(project), "--output-dir", str(tmp_path / "out"), "--policy", str(policy)])

    assert result == 1
    assert "policy file does not exist" in capsys.readouterr().err


def test_policy_reports_are_integrated_when_policy_is_used(tmp_path, monkeypatch):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[capabilities]",
                'deny = ["code_execution"]',
                "[mcp]",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = true",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--policy",
            str(policy),
            "--html",
            "--pretty",
        ]
    )

    assert result == 0
    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")
    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")
    summary = summary_path.read_text(encoding="utf-8")

    assert data["policy_review"]["violations"]
    assert "## Policy review" in markdown
    assert "Denied reachable capability detected: code_execution." in markdown
    assert "Policy Review" in html
    assert "Review workflow" in html
    assert "Policy review failed." in html
    assert "agentbom scan . --policy agentbom.toml --enforce-policy" in html
    assert "Denied reachable capability detected: code_execution." in html
    assert "Policy review: failed" in summary
    assert "Mode: advisory" in summary
    assert "Violations: 1" in summary
    assert "Warnings: 1" in summary
    assert "do-not-store" not in json.dumps(data)
    assert "do-not-store" not in markdown
    assert "do-not-store" not in html


def test_policy_warnings_only_pass_with_warnings_and_enforcement_exits_zero(
    tmp_path, monkeypatch, capsys
):
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
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = true",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--policy",
            str(policy),
            "--enforce-policy",
            "--html",
            "--pretty",
        ]
    )

    assert result == 0
    captured = capsys.readouterr()
    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")
    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")
    summary = summary_path.read_text(encoding="utf-8")

    assert data["policy_review"]["passed"] is True
    assert data["policy_review"]["violations"] == []
    assert data["policy_review"]["warnings"]
    assert "Policy review: passed with warnings" in captured.out
    assert "Status: passed with warnings" in markdown
    assert "passed with warnings" in html
    assert "Policy enforcement passed with warnings." in html
    assert "Review warnings before release." in html
    assert "Policy review: passed with warnings" in summary
    assert "do-not-store" not in json.dumps(data)
    assert "do-not-store" not in markdown
    assert "do-not-store" not in html


def test_secret_leak_value_is_redacted_from_all_cli_reports(tmp_path, monkeypatch, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    secret_value = "sk-proj-CLIREDACTSECRET00000000000000000001"
    (project / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
    policy = tmp_path / "agentbom.toml"
    policy.write_text(
        "[secrets]\nwarn_on_detected = true\nblock_leaks = true\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--policy",
            str(policy),
            "--enforce-policy",
            "--html",
            "--sarif",
            "--pretty",
        ]
    )

    captured = capsys.readouterr()
    json_text = (output_dir / "agentbom.json").read_text(encoding="utf-8")
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")
    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")
    sarif = (output_dir / "agentbom.sarif").read_text(encoding="utf-8")
    summary = summary_path.read_text(encoding="utf-8")

    assert result == 1
    assert "Possible OpenAI API key value" in captured.out
    assert "Secret Leak Findings" in markdown
    assert "Secret Leak Findings" in html
    assert "secret_leak_findings" in json_text
    for output in (captured.out, captured.err, json_text, markdown, html, sarif, summary):
        assert secret_value not in output
    assert "[REDACTED]" in json_text
    assert "[REDACTED]" in markdown
    assert "[REDACTED]" in html


def test_policy_builder_includes_detected_values_and_no_external_scripts():
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "repo",
            "generated_by": "agentbom",
            "providers": [{"name": "openrouter", "path": "agent.py", "confidence": "high"}],
            "models": [
                {
                    "type": "model",
                    "name": "gpt-4o",
                    "source_file": "agent.py",
                    "confidence": "high",
                    "evidence": "gpt-4o",
                }
            ],
            "frameworks": [{"name": "crewai", "path": "agent.py", "confidence": "high"}],
            "mcp_servers": [
                {"name": "custom-browser", "path": "mcp.json", "confidence": "medium"}
            ],
            "capabilities": [],
            "dependencies": [],
            "reachable_capabilities": [
                {
                    "capability": "shell_execution",
                    "reachable_from": "gpt-4o",
                    "source_file": "agent.py",
                    "risk": "high",
                    "confidence": "high",
                }
            ],
            "capability_graph": {"nodes": [], "edges": []},
            "policy_findings": [
                {
                    "severity": "medium",
                    "message": "prompt file detected without security policy",
                    "source_file": "AGENTS.md",
                }
            ],
            "repository_risk": {"score": 50, "severity": "high", "rationale": []},
            "secret_references": [
                {"name": "OPENAI_API_KEY", "path": "agent.py", "confidence": "high"}
            ],
            "risks": [],
        }
    )

    assert "<script src" not in html.lower()
    assert "<link" not in html.lower()
    assert "openrouter" in html
    assert "gpt-4o" in html
    assert "crewai" in html
    assert "shell_execution" in html
    assert "custom-browser" in html
    assert "OPENAI_API_KEY" in html
    assert "prompt file detected without security policy" in html
    assert "agentbom install-hook --policy agentbom.toml --mode advisory" in html
    assert "agentbom install-hook --policy agentbom.toml --mode confirm" in html
    assert "agentbom install-hook --policy agentbom.toml --mode enforce" in html
    assert 'data-kind="provider" data-action="warn"' not in html
    assert 'data-kind="model" data-action="warn"' not in html
    assert 'data-kind="framework" data-action="warn"' not in html
    assert 'data-kind="mcp" data-action="warn"' not in html
    assert 'data-kind="capability" data-action="allow"' not in html
    assert 'data-kind="secret" data-action="warn"' in html
    assert 'data-kind="policy_gap" data-action="warn"' in html


def test_html_enforced_policy_failure_shows_fix_guidance():
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "repo",
            "generated_by": "agentbom",
            "providers": [],
            "models": [],
            "frameworks": [],
            "mcp_servers": [],
            "capabilities": [],
            "dependencies": [],
            "reachable_capabilities": [],
            "capability_graph": {"nodes": [], "edges": []},
            "policy_findings": [],
            "repository_risk": {"score": 0, "severity": "low", "rationale": []},
            "secret_references": [],
            "risks": [],
            "policy_review": {
                "mode": "enforced",
                "violations": [
                    {
                        "severity": "high",
                        "rule": "models.deny",
                        "message": "Model denied by policy: gpt-4o.",
                        "source": "agent.py",
                    }
                ],
                "warnings": [],
            },
        }
    )

    assert "Policy enforcement failed." in html
    assert "Fix policy violations before relying on enforcement." in html


def test_html_report_keeps_scripts_inline_and_secret_values_out():
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "repo",
            "generated_by": "agentbom",
            "providers": [],
            "models": [],
            "frameworks": [],
            "mcp_servers": [],
            "capabilities": [],
            "dependencies": [],
            "reachable_capabilities": [],
            "capability_graph": {"nodes": [], "edges": []},
            "policy_findings": [],
            "repository_risk": {"score": 0, "severity": "low", "rationale": []},
            "secret_references": [{"name": "OPENAI_API_KEY", "path": "agent.py"}],
            "risks": [],
        }
    )

    assert "<script src" not in html.lower()
    assert "<link" not in html.lower()
    assert "OPENAI_API_KEY" in html
    assert "do-not-store" not in html
