# AgentBOM

![CI](https://github.com/vlcak27/agentbom/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/ai-agentbom)
![Python](https://img.shields.io/pypi/pyversions/ai-agentbom)
![License](https://img.shields.io/badge/license-MIT-blue)

AgentBOM is a static security scanner for AI-agent repositories. It detects AI
providers, model identifiers, agent frameworks, prompts, MCP servers, secret
references, and risky capabilities that appear reachable from an agent.

It is different from SAST and SBOM tools because it focuses on AI-agent attack
surface: which models, prompts, frameworks, MCP servers, and capabilities appear
connected in the repository. Use SAST for language-specific vulnerability
patterns and SBOM tools for package inventory. Use AgentBOM to review agent
context and statically inferred reachability.

![AgentBOM HTML report preview](docs/assets/html-report-preview.svg)

## Quickstart

Install AgentBOM:

```bash
pip install ai-agentbom
```

Run AgentBOM from the root of the repository you want to review:

```bash
cd path/to/your-agent-repo
agentbom scan . --pretty
```

Create a starter policy and open the HTML review workflow:

```bash
agentbom init
agentbom scan . --policy agentbom.toml --html --open
```

Generate review artifacts:

```bash
agentbom scan . \
  --output-dir agentbom-report \
  --html \
  --mermaid \
  --sarif \
  --pretty
```

AgentBOM does not execute scanned code.

## Policy Review

`agentbom init` creates a safe starter `agentbom.toml`. You can also generate
a suggested policy from current scan findings:

```bash
agentbom scan . --suggest-policy agentbom.toml
```

AgentBOM evaluates policy in advisory mode by default:

```bash
agentbom scan . --policy agentbom.toml --html --open
```

Policy violations do not fail the scan unless enforcement is explicit:

```bash
agentbom scan . --policy agentbom.toml --enforce-policy
```

Every HTML report includes a Policy Workbench that helps build an
`agentbom.toml` from the actual detected providers, models, frameworks,
reachable capabilities, MCP servers, secret references, and policy gaps.
Use it to refine the policy, then run advisory mode before enforcement.
See [policy docs](docs/policy.md) for setup paths and the rollout workflow.

## Install by Platform

macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ai-agentbom
```

Windows 11 / PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install ai-agentbom
```

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ai-agentbom
```

## What It Finds

| Area | Examples |
| --- | --- |
| Providers | OpenAI, Anthropic, Gemini, Ollama, DeepSeek, OpenRouter |
| Models | Modern static model identifiers across OpenAI GPT/o-series, Anthropic Claude 3.x/4.x, Gemini, DeepSeek, Llama/Code Llama, Mistral/Codestral/Mixtral, Qwen, Grok/xAI, Cohere Command, and Perplexity Sonar. Examples: `gpt-5.5`, `gpt-5.1`, `gpt-4o-mini`, `o3-mini`, `claude-opus-4.7`, `opus4.7`, `claude-sonnet-4.6`, `claude-3.7-sonnet`, `gemini-3.1-pro`, `gemini-3.1-flash`, `deepseek-r1`, `llama-3.3-70b-instruct`, `qwen2.5-coder`, `grok-4`, `command-r-plus`, `sonar-pro`, plus OpenRouter/LiteLLM/provider-prefixed strings such as `openrouter/anthropic/claude-opus-4.7` and `litellm/openai/gpt-5.5`. |
| Frameworks | LangChain, LangGraph, LlamaIndex, CrewAI, AutoGen/AG2, Semantic Kernel, Pydantic AI, OpenAI Agents SDK, Claude Agent SDK, Mastra, Google ADK, Vercel AI SDK, LiteLLM, Instructor, Haystack, DSPy, LangServe |
| Prompts | `AGENTS.md`, `CLAUDE.md`, `prompts/*.md`, prompt YAML |
| MCP | `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, nested Cursor/Claude MCP config paths |
| MCP server risk | filesystem, shell/process, browser/network, database, cloud, secrets/env, unknown/custom servers |
| Capabilities | shell, code execution, network, database, cloud, MCP tool invocation |
| Secret references | credential names such as `OPENAI_API_KEY`, never values |
| Dependencies | deterministic AI-relevant dependency extraction from Python, JavaScript, Rust, and Go manifests |
| Policy gaps | prompt files, MCP config, shell/cloud access without policy documentation |

Model examples are representative of current detector coverage, not an exhaustive catalog.

Findings include source paths, confidence, reviewer-facing rationale, and
mitigation signals where static evidence is available.
## Reports

Start with repository risk, review priorities, reachable capabilities, MCP
security analysis, policy findings, and Changes since baseline.

Diff-aware scans compare the current report with a baseline JSON report:

```bash
agentbom scan . --baseline agentbom-baseline.json --fail-on-new high --sarif --html --pretty
```

`--fail-on-new` accepts `low`, `medium`, `high`, or `critical`. It evaluates
new providers, capabilities, MCP servers, secret references, and policy findings
introduced since the baseline.

See the [report guide](docs/report-guide.md) for field definitions and reviewer
workflow.

## GitHub Action

Use the action in pull requests to publish reports and a workflow job summary.
When `GITHUB_STEP_SUMMARY` is available, AgentBOM summarizes repository risk,
detected AI surface, reachable capabilities, and generated report files directly
in the GitHub Actions run.

```yaml
name: AgentBOM

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AgentBOM
        uses: vlcak27/agentbom@v0.7.0
        with:
          path: .
          fail-on: none
          sarif-upload: false
          html: true
          output-dir: agentbom-report

      - name: Upload AgentBOM reports
        uses: actions/upload-artifact@v4
        with:
          name: agentbom-report
          path: agentbom-report/
```

Enable SARIF upload only when you want GitHub code scanning alerts:

```yaml
permissions:
  contents: read
  security-events: write
```

More details: [GitHub Action docs](docs/github-action.md).

## Security Model

AgentBOM is designed for safe repository review:

- static analysis only
- does not execute scanned code
- does not import scanned modules
- does not execute MCP servers
- does not contact networks during scanning
- skips files larger than 1 MB
- skips binary-looking files
- does not follow symlink loops
- records secret names only, never secret values
- works offline and emits deterministic output for the same input repository

## Limitations

- Findings are review signals, not exploit verification.
- Reachability is inferred from nearby static evidence, not runtime traces.
- False positives and missed detections are possible.
- Detector coverage is intentionally AI-agent focused, not general SAST.
- Dependency parsing is deterministic and limited, not a full lockfile solver.
- AgentBOM is not an SBOM, SPDX, or CycloneDX replacement.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

Or run the project check:

```bash
make check
```

Useful docs:

- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
