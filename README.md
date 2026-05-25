# AgentBOM

![CI](https://github.com/vlcak27/agentbom/actions/workflows/ci.yml/badge.svg)
[![Precision Corpus](https://github.com/vlcak27/agentbom/actions/workflows/precision-corpus.yml/badge.svg)](https://github.com/vlcak27/agentbom/actions/workflows/precision-corpus.yml)
![PyPI](https://img.shields.io/pypi/v/ai-agentbom)
![Python](https://img.shields.io/pypi/pyversions/ai-agentbom)
![License](https://img.shields.io/badge/license-MIT-blue)

## What AgentBOM Is

AgentBOM is a local-first security guard for AI-agent repositories. It combines
a fast static pre-commit guard with optional experimental RunBOM runtime
evidence.

AI-agent repos often mix prompts, tool permissions, MCP config, and API keys.
AgentBOM gives you a local review signal before risky changes enter git.

- Activate once with `agentbom activate`.
- Commit normally with the static local guard.
- Use `agentbom scan` and pre-commit for static-only review.
- Optionally run `agentbom run` for best-effort Python runtime evidence.
- Keep RunBOM separate from enforcement: it is not a sandbox and does not
  enforce policy yet.

## Quickstart

```bash
pip install ai-agentbom
cd my-agent-repo
agentbom activate
git commit
```

Normal commits use the static local guard installed by `agentbom activate`.
`agentbom scan` and the local guard do not execute scanned code.

Optional runtime evidence:

```bash
agentbom run
```

`agentbom run` intentionally executes the configured or autodetected command
under experimental Python-focused instrumentation. JSON artifacts are written
for machines and CI; terminal output is the developer summary.

## What It Catches

- likely AI/API key leaks, with values redacted
- risky shell or code execution capabilities
- MCP server exposure
- AI provider or model usage outside policy

## Demo

Passing commit:

```text
AgentBOM OK
No policy violations found.
```

Blocked commit:

```text
AgentBOM blocked this commit

2 blocking finding(s)
Highest severity: critical

CRITICAL Possible OpenAI API key value
.env:1
Why: likely credential value found in a committed file.
Fix: remove the key, rotate it, and keep secrets in environment variables or a secret manager.
Secret value redacted.
```

The local guard can block commits based on configured policy. Blocked output
shows source, Why, Fix, and whether a secret value was redacted. Static findings
are review signals, not exploit proof. Static capability findings mean
code/config appears capable, not that it executed.

## Recommended Workflow

`agentbom activate` creates or reuses `agentbom.toml` and installs a repo-local
pre-commit guard. The default mode is `confirm`: passing commits print
`AgentBOM OK`, and AgentBOM asks before committing when policy violations are
found. Activation only affects this local clone and does not overwrite an
existing `agentbom.toml` unless `--force` is passed.

```bash
agentbom status
agentbom scan . --policy agentbom.toml --html --open
```

Activation presets:

- `safe`: default, good for normal use.
- `audit`: observe without blocking.
- `strict`: stronger policy for sensitive repos.

`agentbom activate --strict` remains available as an alias for
`agentbom activate --preset strict`.

## Policy Review

Policy review is advisory by default:

```bash
agentbom scan . --policy agentbom.toml --pretty
```

Make policy violations fail a scan only when you opt in:

```bash
agentbom scan . --policy agentbom.toml --enforce-policy
```

The HTML report includes a Policy Workbench for generating and refining
`agentbom.toml` from detected providers, models, frameworks, reachable
capabilities, MCP servers, secret references, and policy gaps.

See [policy docs](docs/policy.md) for policy format, rollout, local guard
modes, and bypass behavior.

## Local Guard

Install a repo-local pre-commit guard:

```bash
agentbom activate
```

Modes:

- `advisory` allows commits and warns on policy violations.
- `confirm` asks before committing when violations exist.
- `enforce` blocks commits when violations exist.

The hook is local to the current repository under `.git/hooks/pre-commit`.
Disable it with:

```bash
agentbom deactivate
```

Troubleshooting prompt or PATH issues: [troubleshooting](docs/troubleshooting.md).

## RunBOM

RunBOM is an experimental, optional runtime evidence mode:

```bash
agentbom activate
agentbom run
```

`agentbom activate` installs the static local guard. It can also configure
`[runbom]` in `agentbom.toml` when a safe test or runtime command is detected.
`agentbom run` intentionally executes the configured command, or an
autodetected command, under best-effort Python runtime instrumentation.

Autodetection prefers simple commands such as:

- `python -m pytest tests/agent_runtime`
- `python -m pytest tests/runbom`
- `python -m pytest`
- npm, pnpm, or bun test scripts when detected

RunBOM prints a human-readable terminal summary and writes machine-readable
artifacts:

```text
AgentBOM RunBOM OK

Runtime summary:
  153 events observed
  57 unique events
  Highest risk: high

Top runtime signals:
  HIGH env.read OPENAI_API_KEY
       Why: agent read an AI provider credential variable name.
       Note: secret value was not recorded.

  HIGH filesystem.read .env
       Why: agent read a common local secrets file.
       Fix: avoid reading local secrets files during agent runtime checks unless expected.

Artifacts:
  .agentbom/runbom-summary.json
  .agentbom/runbom.jsonl
```

The terminal output shows the developer summary and at most the top runtime
signals. JSON artifacts are for machines and CI:

- `.agentbom/runbom.jsonl`
- `.agentbom/runbom-summary.json`

`.agentbom/runbom-summary.json` is the machine-readable summary.
`.agentbom/runbom.jsonl` is the raw event log. Events are classified with risk
and tags, but secret values are never recorded. High-risk runtime evidence does
not fail the command by itself.

RunBOM is Python-focused and best-effort. It is not a sandbox, does not enforce
policy yet, and is not part of pre-commit by default.

## What It Finds

| Area | Examples |
| --- | --- |
| Providers and models | OpenAI, Anthropic, Gemini, Ollama, OpenRouter, GPT/o-series, Claude, Gemini, Llama, Mistral, Qwen, Grok, Cohere, Perplexity |
| Frameworks | LangChain, LangGraph, LlamaIndex, CrewAI, AutoGen/AG2, Semantic Kernel, Pydantic AI, OpenAI Agents SDK, Mastra, Vercel AI SDK, LiteLLM |
| Prompts | `AGENTS.md`, `CLAUDE.md`, `prompts/*.md`, prompt YAML |
| MCP | `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, Cursor/Claude MCP config paths |
| Capabilities | shell, code execution, network, database, cloud, MCP tool invocation |
| Secret references | credential names such as `OPENAI_API_KEY`, never values |
| Secret leak findings | likely AI/API credential values, always redacted |
| Policy gaps | prompt files, MCP config, shell/cloud access without policy documentation |

Findings include source paths, confidence, reviewer-facing rationale, and
mitigation signals where static evidence is available.

## Reports

![AgentBOM HTML report preview](docs/assets/html-report-preview.svg)

Generate review artifacts:

```bash
agentbom scan . --output-dir agentbom-report --html --mermaid --sarif --pretty
```

Diff-aware scans compare the current report with a baseline JSON report:

```bash
agentbom scan . --baseline agentbom-baseline.json --fail-on-new high --sarif --html --pretty
```

`--fail-on-new` accepts `low`, `medium`, `high`, or `critical`.

See the [report guide](docs/report-guide.md) for field definitions and reviewer
workflow.

## GitHub Action

Use the action in pull requests to publish reports and a workflow job summary.

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
        uses: vlcak27/agentbom@v0.8.0
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

Static scan and local guard:

- `agentbom scan` and the local guard are static-only
- does not execute scanned code
- does not import scanned modules
- does not execute MCP servers
- does not contact networks during scanning
- skips files larger than 1 MB
- skips binary-looking files
- does not follow symlink loops
- records secret references by name and likely credential leaks with redacted
  metadata only, never secret values
- works offline and emits deterministic output for the same input repository

RunBOM:

- optional
- intentionally executes the configured or autodetected command
- records best-effort Python runtime evidence
- prints a human-readable terminal summary
- writes JSON artifacts under `.agentbom/`
- never records secret values
- not a sandbox
- no policy enforcement yet

## Limitations

- Findings are review signals, not exploit verification.
- Reachability is inferred from nearby static evidence, not runtime traces.
- False positives and missed detections are possible.
- AgentBOM is AI-agent focused. Use SAST for language-specific vulnerability
  patterns and SBOM tools for package inventory.
- AI/API credential leak checks are focused review signals and are not a
  replacement for full secret scanners such as Gitleaks or TruffleHog.
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
- [Troubleshooting](docs/troubleshooting.md)
- [RunBOM](docs/runbom.md)
