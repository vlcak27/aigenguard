from __future__ import annotations

import json
from pathlib import Path

from aigenguard.html_report import render_html
from aigenguard.report import render_markdown
from aigenguard.scanner import MAX_FILE_SIZE, scan_path


def assert_reachable_contains(items, expected):
    assert any(
        all(item.get(key) == value for key, value in expected.items())
        for item in items
    )


def test_scanner_ignores_large_files_and_detects_prompt_policy_risk(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "large.py").write_bytes(b"openai" * (MAX_FILE_SIZE // 6 + 1))

    data = scan_path(project)

    assert data["prompts"] == [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}]
    assert data["providers"] == []
    assert {"severity": "low", "reason": "prompt files detected without a policy file"} in data["risks"]


def test_scanner_detects_medium_capabilities_and_policy_file(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("import sqlite3\nimport boto3\nrequests.get('https://example.com')\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "SECURITY.md").write_text("policy", encoding="utf-8")

    data = scan_path(project)

    capability_names = {item["name"] for item in data["capabilities"]}
    assert {"network", "database", "cloud"} <= capability_names
    assert {"severity": "medium", "reason": "network, database, or cloud capability detected"} in data["risks"]
    assert not any(risk["severity"] == "low" for risk in data["risks"])


def test_provider_framework_detection_skips_docs(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("openai langchain", encoding="utf-8")
    (project / "AGENTS.md").write_text("openai langchain", encoding="utf-8")
    (project / "agent.yaml").write_text("provider: anthropic\nframework: crewai\n", encoding="utf-8")
    (project / "agent.ts").write_text("import OpenAI from 'openai';\n", encoding="utf-8")

    data = scan_path(project)

    assert {"name": "openai", "path": "README.md", "confidence": "low"} not in data["providers"]
    assert {"name": "langchain", "path": "AGENTS.md", "confidence": "low"} not in data["frameworks"]
    assert {"name": "anthropic", "path": "agent.yaml", "confidence": "medium"} in data["providers"]
    assert {"name": "crewai", "path": "agent.yaml", "confidence": "medium"} in data["frameworks"]
    assert {"name": "openai", "path": "agent.ts", "confidence": "high"} in data["providers"]


def test_provider_framework_fixture_covers_new_sdk_and_env_patterns():
    project = Path(__file__).parent / "fixtures" / "provider_framework_agent"

    data = scan_path(project)

    providers = {(item["name"], item["path"], item["confidence"]) for item in data["providers"]}
    frameworks = {(item["name"], item["path"], item["confidence"]) for item in data["frameworks"]}
    models = {(item["name"], item["source_file"], item["confidence"]) for item in data["models"]}
    dependencies = {
        (item["name"], item["category"], item["path"], item["confidence"])
        for item in data["dependencies"]
    }
    secrets = {(item["name"], item["path"], item["confidence"]) for item in data["secret_references"]}

    assert ("ollama", "ollama_agent.py", "high") in providers
    assert ("deepseek", "deepseek_agent.py", "high") in providers
    assert ("gemini", "gemini_langgraph_agent.py", "high") in providers
    assert ("openrouter", "openrouter_agent.ts", "high") in providers
    assert ("openrouter", "agent.yaml", "medium") in providers
    assert ("langgraph", "gemini_langgraph_agent.py", "high") in frameworks
    assert ("langgraph", "agent.yaml", "medium") in frameworks
    assert ("llama3.1", "ollama_agent.py", "high") in models
    assert ("deepseek-chat", "deepseek_agent.py", "high") in models
    assert ("gemini-2.0-flash", "gemini_langgraph_agent.py", "high") in models
    assert ("gpt-4o", "openrouter_agent.ts", "high") in models
    assert ("google-genai", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("ollama", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("openrouter", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("langgraph", "ai_framework", "requirements.txt", "low") in dependencies
    assert ("DEEPSEEK_API_KEY", "deepseek_agent.py", "high") in secrets
    assert (
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "gemini_langgraph_agent.py",
        "high",
    ) in secrets
    assert ("OPENROUTER_API_KEY", "openrouter_agent.ts", "high") in secrets


def test_agents_md_is_prompt_only_for_ai_terms(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("openai langchain gpt-4o", encoding="utf-8")

    data = scan_path(project)

    assert data["prompts"] == [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}]
    assert data["providers"] == []
    assert data["frameworks"] == []
    assert data["models"] == []


def test_scanner_detects_concrete_models_in_code_and_config_files(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("model = 'gpt-4o'\nfallback = 'gpt-5'\n", encoding="utf-8")
    (project / "models.js").write_text("const models = ['gpt-4', 'gpt-4.1', 'llama3'];\n", encoding="utf-8")
    (project / "config.ts").write_text("const model = 'mistral-large';\n", encoding="utf-8")
    (project / "agent.json").write_text('{"model": "claude-3-opus"}\n', encoding="utf-8")
    (project / "agent.yaml").write_text(
        "models:\n- claude-3\n- claude-3-sonnet\n- claude-3-haiku\n- gemini-pro\n- gemini-1.5-pro\n- gemini-2.0-flash\n",
        encoding="utf-8",
    )
    (project / "settings.toml").write_text(
        'provider = "gemini"\nframework = "semantic-kernel"\nmodel = "gemini-pro"\n',
        encoding="utf-8",
    )

    data = scan_path(project)
    models = {(item["name"], item["source_file"], item["confidence"]) for item in data["models"]}

    assert ("gpt-4o", "agent.py", "high") in models
    assert ("gpt-5", "agent.py", "high") in models
    assert ("gpt-4", "models.js", "high") in models
    assert ("gpt-4.1", "models.js", "high") in models
    assert ("llama3", "models.js", "high") in models
    assert ("mistral-large", "config.ts", "high") in models
    assert ("claude-3-opus", "agent.json", "medium") in models
    assert ("claude-3", "agent.yaml", "medium") in models
    assert ("claude-3-sonnet", "agent.yaml", "medium") in models
    assert ("claude-3-haiku", "agent.yaml", "medium") in models
    assert ("gemini-pro", "agent.yaml", "medium") in models
    assert ("gemini-1.5-pro", "agent.yaml", "medium") in models
    assert ("gemini-2.0-flash", "agent.yaml", "medium") in models
    assert ("gemini-pro", "settings.toml", "medium") in models
    assert {"name": "gemini", "path": "settings.toml", "confidence": "medium"} in data["providers"]
    assert {"name": "semantic_kernel", "path": "settings.toml", "confidence": "medium"} in data["frameworks"]
    assert all(item["type"] == "model" for item in data["models"])
    assert all(item["evidence"] == item["name"] for item in data["models"])


def test_model_detection_skips_markdown_docs_and_keeps_providers_separate(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("gpt-4o openai", encoding="utf-8")
    (project / "AGENTS.md").write_text("claude-3-opus anthropic", encoding="utf-8")
    (project / "agent.py").write_text(
        "from openai import OpenAI\nmodel = 'gpt-4o'\napi_key = 'do-not-store'\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "type": "model",
        "name": "gpt-4o",
        "source_file": "agent.py",
        "confidence": "high",
        "evidence": "gpt-4o",
    } in data["models"]
    assert not any(item["source_file"].endswith(".md") for item in data["models"])
    assert {"name": "openai", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert "do-not-store" not in str(data)


def test_secret_references_are_normalized_and_deduplicated(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from openai import OpenAI",
                "api_key = 'do-not-store'",
                "openai_api_key = api_key",
                "OPENAI_API_KEY = openai_api_key",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_references"] == [
        {"name": "OPENAI_API_KEY", "path": "agent.py", "confidence": "high"}
    ]
    assert "do-not-store" not in str(data)


def test_repository_risk_score_uses_reachability_secrets_and_missing_policy(tmp_path):
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
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")

    data = scan_path(project)

    assert data["repository_risk"] == {
        "score": 90,
        "severity": "critical",
        "rationale": [
            "high-risk reachable capability detected: code_execution",
            "shell or code execution is present or reachable",
            "secret references were detected",
            "policy controls are missing or incomplete",
        ],
    }
    assert "do-not-store" not in str(data["repository_risk"])


def test_repository_risk_score_is_low_without_risk_factors(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("documentation only\n", encoding="utf-8")

    data = scan_path(project)

    assert data["repository_risk"] == {
        "score": 0,
        "severity": "low",
        "rationale": ["no repository-level risk factors detected"],
    }


def test_python_ast_detection_finds_security_relevant_constructs(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess as sp",
                "import httpx as client",
                "from anthropic import Anthropic",
                "from mcp import ClientSession",
                "from openai import OpenAI",
                "",
                "def run(session: ClientSession):",
                "    OpenAI()",
                "    Anthropic()",
                "    sp.run(['echo', 'hello'])",
                "    eval('1 + 1')",
                "    client.get('https://example.com')",
                "    session.call_tool('search', {'query': 'agent'})",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {"name": "openai", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert {"name": "anthropic", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert {
        "name": "shell",
        "path": "agent.py",
        "confidence": "high",
        "policy_status": "undocumented",
    } in data["capabilities"]
    assert {
        "name": "code_execution",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]
    assert {"name": "network", "path": "agent.py", "confidence": "high"} in data["capabilities"]
    assert {
        "name": "mcp_tool_invocation",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]


def test_dependency_analysis_parses_pyproject_and_requirements(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'dependencies = ["langchain>=0.2", "pydantic-ai", "mcp", "requests"]',
                "",
                "[project.optional-dependencies]",
                'sandbox = ["e2b>=1"]',
            ]
        ),
        encoding="utf-8",
    )
    (project / "requirements.txt").write_text(
        "\n".join(
            [
                "crewai==0.80.0",
                "fastmcp>=2",
                "docker[ssh]>=7",
                "pytest",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "langchain",
        "category": "ai_framework",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "pydantic-ai",
        "category": "ai_framework",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "mcp",
        "category": "mcp",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "e2b",
        "category": "sandbox_runtime",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "crewai",
        "category": "ai_framework",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert {
        "name": "fastmcp",
        "category": "mcp",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert {
        "name": "docker",
        "category": "sandbox_runtime",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert not any(item["name"] == "pytest" for item in data["dependencies"])


def test_dependency_analysis_parses_js_rust_and_go_manifests(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "@mastra/core": "^0.1.0",
                    "ai": "^4.0.0",
                    "@ai-sdk/openai": "^1.0.0",
                    "left-pad": "^1.3.0",
                },
                "devDependencies": {
                    "@anthropic-ai/claude-agent-sdk": "^0.1.0",
                },
            }
        ),
        encoding="utf-8",
    )
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"@openai/agents": "^0.1.0"}},
                    "node_modules/@anthropic-ai/sdk": {"version": "0.1.0"},
                }
            }
        ),
        encoding="utf-8",
    )
    (project / "pnpm-lock.yaml").write_text(
        "\n".join(
            [
                "dependencies:",
                "  '@google/genai':",
                "    specifier: ^1.0.0",
                "    version: 1.0.0",
                "packages:",
                "  '@mastra/core@0.1.0':",
                "    resolution: {}",
            ]
        ),
        encoding="utf-8",
    )
    (project / "yarn.lock").write_text(
        "\n".join(
            [
                '"@ai-sdk/anthropic@^1.0.0":',
                "  version 1.0.0",
                '"ai@^4.0.0":',
                "  version 4.0.0",
            ]
        ),
        encoding="utf-8",
    )
    (project / "Cargo.toml").write_text(
        "\n".join(
            [
                "[dependencies]",
                'async-openai = "0.28"',
                'rig-core = "0.10"',
                "",
                "[dev-dependencies]",
                'serde = "1"',
            ]
        ),
        encoding="utf-8",
    )
    (project / "go.mod").write_text(
        "\n".join(
            [
                "module example.com/agent",
                "",
                "require (",
                "    github.com/sashabaranov/go-openai v1.40.0",
                "    github.com/stretchr/testify v1.9.0",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)
    dependencies = {
        (item["name"], item["category"], item["path"], item["confidence"])
        for item in data["dependencies"]
    }

    assert ("@mastra/core", "ai_framework", "package.json", "medium") in dependencies
    assert ("ai", "ai_framework", "package.json", "medium") in dependencies
    assert ("@ai-sdk/openai", "provider_sdk", "package.json", "medium") in dependencies
    assert (
        "@anthropic-ai/claude-agent-sdk",
        "ai_framework",
        "package.json",
        "medium",
    ) in dependencies
    assert ("@openai/agents", "ai_framework", "package-lock.json", "medium") in dependencies
    assert ("@anthropic-ai/sdk", "provider_sdk", "package-lock.json", "medium") in dependencies
    assert ("@google/genai", "provider_sdk", "pnpm-lock.yaml", "medium") in dependencies
    assert ("@mastra/core", "ai_framework", "pnpm-lock.yaml", "medium") in dependencies
    assert ("@ai-sdk/anthropic", "provider_sdk", "yarn.lock", "medium") in dependencies
    assert ("ai", "ai_framework", "yarn.lock", "medium") in dependencies
    assert ("async-openai", "provider_sdk", "Cargo.toml", "medium") in dependencies
    assert (
        "github.com/sashabaranov/go-openai",
        "provider_sdk",
        "go.mod",
        "medium",
    ) in dependencies
    assert not any(item["name"] in {"left-pad", "serde"} for item in data["dependencies"])


def test_dependency_analysis_keeps_js_only_ai_package_out_of_python_manifests(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "requirements.txt").write_text("ai==1.0.0\n", encoding="utf-8")

    data = scan_path(project)

    assert data["dependencies"] == []


def test_generic_secret_names_without_provider_context_are_ignored(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "api_key = 'do-not-store'\ntoken = 'do-not-store'\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_references"] == []


def test_secret_reference_detection_does_not_store_secret_values(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    secret_value = "sk-do-not-store-this-value"
    (project / "agent.py").write_text(
        f"from openai import OpenAI\nOPENAI_API_KEY = {secret_value!r}\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "OPENAI_API_KEY",
        "path": "agent.py",
        "confidence": "high",
    } in data["secret_references"]
    assert secret_value not in json.dumps(data, sort_keys=True)


def test_secret_leak_detection_reports_redacted_provider_values(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    openai_value = "sk-proj-OPENAISECRET000000000000000000001"
    anthropic_value = "sk-ant-api03-ANTHROPICSECRET0000000000000000001"
    github_value = "ghp_GITHUBSECRET000000000000000000000001"
    google_value = "AIza" + "A" * 33 + "12"
    huggingface_value = "hf_HUGGINGFACESECRET000000000000000001"
    cohere_value = "COHERESECRET0000000000000000000000000001"
    (project / ".env").write_text(
        "\n".join(
            [
                f"OPENAI_API_KEY={openai_value}",
                f"ANTHROPIC_API_KEY={anthropic_value}",
                f"GITHUB_TOKEN={github_value}",
                f"GEMINI_API_KEY={google_value}",
                f"HUGGINGFACE_TOKEN={huggingface_value}",
                f"COHERE_API_KEY={cohere_value}",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    findings = data["secret_leak_findings"]
    assert [
        (item["provider"], item["severity"], item["confidence"], item["line"])
        for item in findings
    ] == [
        ("openai", "critical", "high", 1),
        ("anthropic", "critical", "high", 2),
        ("github", "critical", "high", 3),
        ("google_gemini", "high", "high", 4),
        ("huggingface", "high", "high", 5),
        ("cohere", "high", "high", 6),
    ]
    assert all("[REDACTED]" in item["redacted_evidence"] for item in findings)
    serialized = json.dumps(data, sort_keys=True)
    assert openai_value not in serialized
    assert anthropic_value not in serialized
    assert github_value not in serialized
    assert google_value not in serialized
    assert huggingface_value not in serialized
    assert cohere_value not in serialized


def test_secret_leak_detection_reports_redacted_generic_assignment(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    secret_value = "generic-secret-value-123456789"
    (project / "settings.toml").write_text(
        f'api_key = "{secret_value}"\ntoken = "short"\n',
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_leak_findings"] == [
        {
            "provider": "generic",
            "category": "api_key",
            "severity": "high",
            "confidence": "medium",
            "path": "settings.toml",
            "line": 1,
            "title": "Possible API_KEY value",
            "redacted_evidence": "API_KEY = [REDACTED]",
            "suggested_action": "Value redacted. Remove the key and rotate it.",
        }
    ]
    assert secret_value not in json.dumps(data, sort_keys=True)


def test_secret_leak_detection_ignores_placeholders_and_env_references(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "OPENAI_API_KEY = 'your-api-key'",
                "ANTHROPIC_API_KEY = 'sk-...'",
                "GITHUB_TOKEN = '<API_KEY>'",
                "GEMINI_API_KEY = '${API_KEY}'",
                "api_key = process.env.OPENAI_API_KEY",
                "token = os.environ['OPENAI_API_KEY']",
                "secret = 'changeme'",
                "token = 'dummy'",
                "api_key = 'replace-me'",
                "secret = 'example'",
                "token = 'test'",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_leak_findings"] == []


def test_secret_leak_policy_block_and_warning_modes(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / ".env").write_text(
        "OPENAI_API_KEY=sk-proj-BLOCKSECRET000000000000000000001\n",
        encoding="utf-8",
    )
    blocking_policy = tmp_path / "blocking.toml"
    blocking_policy.write_text(
        "[secrets]\nwarn_on_detected = true\nblock_leaks = true\n",
        encoding="utf-8",
    )
    warning_policy = tmp_path / "warning.toml"
    warning_policy.write_text(
        "[secrets]\nwarn_on_detected = true\nblock_leaks = false\n",
        encoding="utf-8",
    )

    blocked = scan_path(project, policy_path=blocking_policy)
    warned = scan_path(project, policy_path=warning_policy)

    assert blocked["policy_review"]["violations"]
    assert blocked["policy_review"]["violations"][0]["rule"] == "secrets.block_leaks"
    assert warned["policy_review"]["violations"] == []
    assert any(
        item["rule"] == "secrets.warn_on_detected"
        and item["message"] == "Possible OpenAI API key value"
        for item in warned["policy_review"]["warnings"]
    )


def test_secret_leak_findings_are_sorted_deterministically(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "b.py").write_text(
        "API_KEY='generic-secret-value-123456789'\n",
        encoding="utf-8",
    )
    (project / "a.py").write_text(
        "\n".join(
            [
                "TOKEN='another-generic-value-123456789'",
                "OPENAI_API_KEY='sk-proj-SORTSECRET0000000000000000000001'",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert [
        (item["severity"], item["confidence"], item["path"], item["line"], item["provider"])
        for item in data["secret_leak_findings"]
    ] == [
        ("critical", "high", "a.py", 2, "openai"),
        ("high", "medium", "a.py", 1, "generic"),
        ("high", "medium", "b.py", 1, "generic"),
    ]


def test_reachable_capabilities_connect_model_to_risky_capabilities(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import boto3",
                "import httpx",
                "import subprocess",
                "model = 'gpt-4o'",
                "httpx.get('https://example.com')",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "code_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "high",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["shell_execution"],
    })
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "cloud_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })


def test_high_risk_reachability_includes_rationale_and_mitigations(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "model = 'gpt-4o'",
                "# Human approval required before tools run inside a sandbox.",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)
    finding = next(
        item
        for item in data["reachable_capabilities"]
        if item["capability"] == "code_execution"
    )

    assert finding["risk"] == "high"
    assert finding["mitigations"] == ["human approval control", "sandbox control"]
    assert finding["confidence_score"] == 90
    rationale = " ".join(finding["rationale"])
    assert "model gpt-4o can reach code_execution in agent.py" in rationale
    assert "same source file" in rationale
    assert "risk is retained for review" in rationale


def test_reachable_capabilities_use_framework_when_no_model_is_detected(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from langchain.chat_models import ChatOpenAI",
                "requests.get('https://example.com')",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert len(data["reachable_capabilities"]) == 1
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "langchain",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })


def test_reachability_tracks_prompt_tool_and_network_paths(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import requests",
                "from mcp import ClientSession",
                "model = 'gpt-4o'",
                "prompt = input('task: ')",
                "session = ClientSession()",
                "session.call_tool('search', {'query': prompt})",
                "requests.get('https://example.com')",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["prompt_input", "tool_invocation", "network_execution"],
    })


def test_reachable_capabilities_can_cross_files_with_lower_confidence(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "config.py").write_text("model = 'gpt-4o'\n", encoding="utf-8")
    (project / "tools.py").write_text(
        "import os\nos.system('echo hello')\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert len(data["reachable_capabilities"]) == 1
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "code_execution",
        "reachable_from": "gpt-4o",
        "source_file": "tools.py",
        "risk": "high",
        "confidence": "medium",
        "confidence_score": 85,
        "paths": ["shell_execution"],
    })


def test_scanner_detects_autonomous_execution_capability(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "model = 'gpt-4o'",
                "while True:",
                "    agent.run()",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "autonomous_execution",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]
    assert {
        "severity": "high",
        "reason": "shell, code execution, or autonomous execution capability detected",
    } in data["risks"]
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "autonomous_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "high",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["tool_invocation"],
    })


def test_autonomous_execution_in_tests_is_lower_confidence(tmp_path):
    project = tmp_path / "agent"
    tests_dir = project / "tests"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_agent.py").write_text(
        "\n".join(
            [
                "model = 'gpt-4o'",
                "while True:",
                "    agent.run()",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "autonomous_execution",
        "path": "tests/test_agent.py",
        "confidence": "medium",
    } in data["capabilities"]
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "autonomous_execution",
        "reachable_from": "gpt-4o",
        "source_file": "tests/test_agent.py",
        "risk": "high",
        "confidence": "medium",
        "confidence_score": 85,
        "paths": ["tool_invocation"],
    })


def test_single_agent_run_call_is_not_autonomous_execution(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "model = 'gpt-4o'\nagent.run('one task')\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "autonomous_execution",
        "path": "agent.py",
        "confidence": "high",
    } not in data["capabilities"]
    assert not any(
        item["capability"] == "autonomous_execution"
        for item in data["reachable_capabilities"]
    )


def test_scanner_detects_autonomous_execution_config_flags(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.yaml").write_text(
        "model: gpt-4o\nauto_run: true\ncontinuous_mode: true\nmax_iterations: 100\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["capabilities"] == [
        {"name": "autonomous_execution", "path": "agent.yaml", "confidence": "medium"}
    ]
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "autonomous_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.yaml",
        "risk": "high",
        "confidence": "medium",
        "confidence_score": 90,
        "paths": ["tool_invocation"],
    })


def test_policy_findings_report_missing_policy_controls(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "agent.py").write_text(
        "import subprocess\nimport boto3\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text("{}", encoding="utf-8")

    data = scan_path(project)

    assert {
        "severity": "low",
        "message": "prompt file detected without security policy",
        "source_file": "AGENTS.md",
        "policy_status": "undocumented",
    } in data["policy_findings"]
    assert {
        "severity": "high",
        "message": "shell execution detected without restrictions",
        "source_file": "agent.py",
        "policy_status": "undocumented",
    } in data["policy_findings"]
    assert {
        "severity": "medium",
        "message": "cloud access detected without policy file",
        "source_file": "agent.py",
        "policy_status": "undocumented",
    } in data["policy_findings"]
    assert {
        "severity": "medium",
        "message": "MCP config detected without policy documentation",
        "source_file": "mcp.json",
        "policy_status": "undocumented",
    } in data["policy_findings"]


def test_policy_findings_are_empty_when_policy_file_exists(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "agent.py").write_text(
        "import subprocess\nimport boto3\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text("{}", encoding="utf-8")
    (project / "SECURITY.md").write_text("policy", encoding="utf-8")

    data = scan_path(project)

    assert data["policy_findings"] == []


def test_mcp_security_analysis_extracts_safe_server_metadata(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / ".mcp.json").write_text(
        """
        {
          "mcpServers": {
            "safe-docs": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-memory", "--api-key", "do-not-store"],
              "env": {
                "DOCS_API_KEY": "do-not-store"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "safe-docs",
            "path": ".mcp.json",
            "confidence": "medium",
            "kind": "server",
            "parse_status": "parsed",
            "risk": "high",
            "risk_categories": ["secrets_env_access"],
            "rationale": ["server declares environment variables: DOCS_API_KEY"],
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory", "--api-key", "[redacted]"],
            "env": ["DOCS_API_KEY"],
            "transport": "stdio",
            "package": "@modelcontextprotocol/server-memory",
            "policy_status": "undocumented",
        }
    ]
    assert "do-not-store" not in str(data)
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "mcp_tool_invocation",
        "reachable_from": "prompt configuration",
        "source_file": ".mcp.json",
        "risk": "high",
        "confidence": "low",
        "confidence_score": 70,
        "paths": ["tool_invocation"],
        "mcp_server": "safe-docs",
    })


def test_mcp_security_analysis_classifies_filesystem_and_shell_servers(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "from langchain.chat_models import ChatOpenAI\n",
        encoding="utf-8",
    )
    (project / ".cursor").mkdir()
    (project / ".cursor" / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            },
            "shell-runner": {
              "command": "python",
              "args": ["-m", "local_shell_server"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    servers = {item["name"]: item for item in data["mcp_servers"]}
    assert servers["filesystem"]["risk"] == "high"
    assert "filesystem_access" in servers["filesystem"]["risk_categories"]
    assert servers["filesystem"]["package"] == "@modelcontextprotocol/server-filesystem"
    assert servers["shell-runner"]["risk"] == "high"
    assert "shell_process_execution" in servers["shell-runner"]["risk_categories"]
    assert servers["shell-runner"]["package"] == "local_shell_server"
    assert any(
        item.get("mcp_server") == "filesystem"
        and item.get("reachable_from") == "langchain"
        for item in data["reachable_capabilities"]
    )


def test_invalid_mcp_json_is_reported_without_crashing(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "claude_desktop_config.json").write_text("{not-json", encoding="utf-8")
    (project / "AGENTS.md").write_text("Agent instructions are present.", encoding="utf-8")

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "claude_desktop_config.json",
            "path": "claude_desktop_config.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "invalid_json",
            "risk": "low",
            "risk_categories": ["unknown_custom_server"],
            "rationale": ["MCP config could not be parsed as JSON"],
            "policy_status": "undocumented",
        }
    ]
    assert not any(
        item.get("capability") == "mcp_tool_invocation"
        for item in data["reachable_capabilities"]
    )


def test_empty_mcp_config_is_inventory_only_and_non_high_with_prompt(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("Agent instructions are present.", encoding="utf-8")
    (project / "mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "mcp.json",
            "path": "mcp.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "no_servers",
        }
    ]
    assert not any(
        item.get("capability") == "mcp_tool_invocation"
        for item in data["reachable_capabilities"]
    )


def test_mcp_output_order_is_deterministic(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "z-server": {"command": "node", "args": ["z.js"]},
            "a-server": {"command": "node", "args": ["a.js"]}
          }
        }
        """,
        encoding="utf-8",
    )

    first = scan_path(project)
    second = scan_path(project)

    assert [item["name"] for item in first["mcp_servers"]] == ["a-server", "z-server"]
    assert first["mcp_servers"] == second["mcp_servers"]


def test_mcp_security_fixture_covers_safe_server_env_redaction_and_reachability():
    project = Path(__file__).parent / "fixtures" / "mcp_safe_agent"

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "docs-search",
            "path": ".mcp.json",
            "confidence": "medium",
            "kind": "server",
            "parse_status": "parsed",
            "risk": "high",
            "risk_categories": ["browser_network_access", "secrets_env_access"],
            "rationale": [
                "server name or config suggests browser or network access",
                "server declares environment variables: DOCS_API_KEY",
            ],
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory", "--token", "[redacted]"],
            "env": ["DOCS_API_KEY"],
            "transport": "stdio",
            "package": "@modelcontextprotocol/server-memory",
            "policy_status": "undocumented",
        },
        {
            "name": "memory-cache",
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
            "policy_status": "undocumented",
        },
    ]
    assert "sk-do-not-store" not in str(data)
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "mcp_tool_invocation",
        "reachable_from": "prompt configuration",
        "source_file": ".mcp.json",
        "risk": "high",
        "mcp_server": "docs-search",
        "paths": ["tool_invocation"],
    })


def test_mcp_security_fixture_covers_nested_filesystem_shell_and_ordering():
    project = Path(__file__).parent / "fixtures" / "mcp_risky_agent"

    first = scan_path(project)
    second = scan_path(project)
    servers = {item["name"]: item for item in first["mcp_servers"]}

    assert first["mcp_servers"] == second["mcp_servers"]
    assert [item["name"] for item in first["mcp_servers"]] == [
        "brave-search",
        "filesystem",
        "shell-runner",
    ]
    assert servers["brave-search"]["path"] == ".cursor/mcp.json"
    assert servers["brave-search"]["risk"] == "medium"
    assert servers["brave-search"]["risk_categories"] == ["browser_network_access"]
    assert "shell_process_execution" not in servers["brave-search"]["risk_categories"]
    assert servers["filesystem"]["risk_categories"] == ["filesystem_access"]
    assert servers["shell-runner"]["risk_categories"] == ["shell_process_execution"]
    assert {
        "id": "mcp_server:filesystem",
        "type": "mcp_server",
        "name": "filesystem",
    } in first["capability_graph"]["nodes"]
    assert {
        "source": "mcp_server:filesystem",
        "target": "mcp_risk:filesystem_access",
        "type": "risk",
    } in first["capability_graph"]["edges"]


def test_invalid_mcp_fixture_does_not_create_reachable_tool_invocation():
    project = Path(__file__).parent / "fixtures" / "mcp_invalid_agent"

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "claude_desktop_config.json",
            "path": "claude_desktop_config.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "invalid_json",
            "risk": "low",
            "risk_categories": ["unknown_custom_server"],
            "rationale": ["MCP config could not be parsed as JSON"],
            "policy_status": "undocumented",
        }
    ]
    assert not any(
        item.get("capability") == "mcp_tool_invocation"
        for item in data["reachable_capabilities"]
    )
    assert not any(
        item.get("type") == "mcp_server"
        for item in data["capability_graph"]["nodes"]
    )


def test_mcp_config_alone_does_not_make_unrelated_code_reachable(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["@modelcontextprotocol/server-filesystem"]
            },
            "shell-runner": {"command": "bash"},
            "browser": {"command": "npx", "args": ["@mcp/browser"]},
            "postgres": {"command": "npx", "args": ["@mcp/postgres"]},
            "aws": {"command": "npx", "args": ["@mcp/aws"]},
            "vault": {"command": "npx", "env": {"VAULT_TOKEN": "do-not-store"}}
          }
        }
        """,
        encoding="utf-8",
    )
    (project / "tool.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )

    data = scan_path(project)
    servers = {server["name"]: server for server in data["mcp_servers"]}

    assert {
        "filesystem_access",
        "shell_process_execution",
        "browser_network_access",
        "database_access",
        "cloud_access",
        "secrets_env_access",
    } <= {
        category
        for server in servers.values()
        for category in server.get("risk_categories", [])
    }
    assert all(server["kind"] == "server" for server in servers.values())
    assert not any(
        item.get("capability") == "mcp_tool_invocation"
        for item in data["reachable_capabilities"]
    )


def test_mcp_config_with_framework_evidence_creates_reachable_exposure(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "from langchain.chat_models import ChatOpenAI\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["@modelcontextprotocol/server-filesystem"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert any(server.get("name") == "filesystem" for server in data["mcp_servers"])
    assert_reachable_contains(
        data["reachable_capabilities"],
        {
            "capability": "mcp_tool_invocation",
            "reachable_from": "langchain",
            "source_file": "mcp.json",
            "risk": "high",
            "mcp_server": "filesystem",
            "risk_categories": ["filesystem_access"],
        },
    )


def test_mcp_config_with_prompt_evidence_creates_reachable_exposure(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("Agent instructions are present.", encoding="utf-8")
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["@modelcontextprotocol/server-filesystem"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert_reachable_contains(
        data["reachable_capabilities"],
        {
            "capability": "mcp_tool_invocation",
            "reachable_from": "prompt configuration",
            "source_file": "mcp.json",
            "risk": "high",
            "mcp_server": "filesystem",
            "risk_categories": ["filesystem_access"],
        },
    )


def test_report_wording_separates_mcp_inventory_from_reachable_exposure(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["@modelcontextprotocol/server-filesystem"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)
    markdown = render_markdown(data)
    html = render_html(data)

    assert "MCP Security Analysis" in markdown
    assert "MCP inventory" in markdown
    assert "None detected." in markdown.split("## Reachable Capabilities", 1)[1]
    assert "does not prove runtime reachability" in markdown
    assert "They are not exploit claims." in markdown
    assert "MCP inventory" in html
    assert "static evidence suggests" in html


def test_capability_graph_contains_nodes_and_edges(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from openai import OpenAI",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "requests.get('https://example.com')",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)
    graph = data["capability_graph"]

    assert {
        "id": "provider:openai",
        "type": "provider",
        "name": "openai",
    } in graph["nodes"]
    assert {
        "id": "model:gpt-4o",
        "type": "model",
        "name": "gpt-4o",
    } in graph["nodes"]
    assert {
        "id": "framework:langchain",
        "type": "framework",
        "name": "langchain",
    } in graph["nodes"]
    assert {
        "id": "capability:network_access",
        "type": "capability",
        "name": "network_access",
    } in graph["nodes"]
    assert {
        "source": "model:gpt-4o",
        "target": "provider:openai",
        "type": "uses",
    } in graph["edges"]
    assert {
        "source": "model:gpt-4o",
        "target": "capability:code_execution",
        "type": "reaches",
    } in graph["edges"]
    assert {
        "source": "framework:langchain",
        "target": "capability:network_access",
        "type": "enables",
    } in graph["edges"]
    assert graph["nodes"] == sorted(graph["nodes"], key=lambda item: (item["type"], item["id"]))
    assert graph["edges"] == sorted(
        graph["edges"], key=lambda item: (item["source"], item["target"], item["type"])
    )
