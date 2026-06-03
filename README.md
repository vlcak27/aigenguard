# AigenGuard

Local-first pre-commit policy guard for AI-agent repositories.

![CI](https://github.com/vlcak27/aigenguard/actions/workflows/ci.yml/badge.svg)
[![Precision Corpus](https://github.com/vlcak27/aigenguard/actions/workflows/precision-corpus.yml/badge.svg)](https://github.com/vlcak27/aigenguard/actions/workflows/precision-corpus.yml)
![PyPI](https://img.shields.io/pypi/v/aigenguard)
![Python](https://img.shields.io/pypi/pyversions/aigenguard)
![License](https://img.shields.io/badge/license-MIT-blue)

AigenGuard helps review AI-agent repositories before risky changes land in git.
It installs a repo-local pre-commit guard and produces deterministic static
review signals for code, prompts, MCP config, policy gaps, and AI/API credential
context.

AI-agent repos often spread important behavior across prompt files, tool
permissions, MCP servers, and credential references. AigenGuard makes those
changes visible in the normal commit workflow.

## Primary Workflow

```bash
pip install aigenguard
cd my-agent-repo
aigenguard activate
git commit
```

`aigenguard activate` creates or reuses `aigenguard.toml` and installs the local
pre-commit guard. After that, commits run the static guard locally.

## Example Blocked Change

```text
AigenGuard blocked this commit

CRITICAL Possible OpenAI API key value
.env:1
Why: likely credential value found in a committed file.
Fix: remove the key, rotate it, and keep secrets in environment variables or a secret manager.
Secret value redacted.
```

The local guard can allow, confirm, or block commits based on configured policy.
Static findings are review signals, not exploit proof.

## Local-First Trust Model

- Static scans run locally and work offline.
- Static scans do not execute scanned code or import scanned modules.
- Static scans do not execute MCP servers or contact networks.
- Secret values are redacted and must not be printed or stored.

## Optional RunBOM Evidence

```bash
aigenguard run
```

RunBOM is optional supporting runtime evidence. It intentionally executes the
configured or autodetected command under experimental Python-focused
instrumentation. It is not the main product, not a sandbox, and not policy
enforcement.

## AgentBOM Compatibility

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain supported during migration. New projects should use `aigenguard` and `aigenguard.toml`.

Policy discovery uses this order:

1. An explicit `--policy` path.
2. `aigenguard.toml` when present.
3. `agentbom.toml` as a compatibility fallback.

Compatibility remains for existing automation:

- `agentbom` CLI alias
- `agentbom` Python import aliases
- `agentbom.toml` fallback
- `agentbom.*` report filenames
- `.agentbom/` runtime artifacts
- `AGENTBOM_SKIP_HOOK` hook bypass alias

## What It Reviews

- likely AI/API key leaks, with values redacted
- risky shell or code execution capabilities
- MCP server exposure
- AI provider or model usage outside policy

## Recommended Workflow

`aigenguard activate` creates or reuses `aigenguard.toml` and installs a
repo-local pre-commit guard. Existing `agentbom.toml` files are reused as a
compatibility fallback. The default mode is `confirm`: passing commits print
`AigenGuard OK`, and the guard asks before committing when policy violations are
found. Activation only affects this local clone and does not overwrite an
existing policy unless `--force` is passed.

```bash
aigenguard status
aigenguard scan . --policy aigenguard.toml --html --open
```

Activation presets:

- `safe`: default, good for normal use.
- `audit`: observe without blocking.
- `strict`: stronger policy for sensitive repos.

`aigenguard activate --strict` remains available as an alias for
`aigenguard activate --preset strict`.

## Policy Review

Policy review is advisory by default:

```bash
aigenguard scan . --policy aigenguard.toml --pretty
```

Make policy violations fail a scan only when you opt in:

```bash
aigenguard scan . --policy aigenguard.toml --enforce-policy
```

The HTML report includes a Policy Workbench for generating and refining
`aigenguard.toml` from detected providers, models, frameworks, reachable
capabilities, MCP servers, secret references, and policy gaps.

See [policy docs](docs/policy.md) for policy format, rollout, local guard
modes, and bypass behavior.

## Local Guard

Install a repo-local pre-commit guard:

```bash
aigenguard activate
```

Modes:

- `advisory` allows commits and warns on policy violations.
- `confirm` asks before committing when violations exist.
- `enforce` blocks commits when violations exist.

The hook is local to the current repository under `.git/hooks/pre-commit`.
Disable it with:

```bash
aigenguard deactivate
```

Troubleshooting prompt or PATH issues: [troubleshooting](docs/troubleshooting.md).

## RunBOM

RunBOM is an experimental, optional runtime evidence mode:

```bash
aigenguard activate
aigenguard run
```

`aigenguard activate` installs the static local guard. It can also configure
`[runbom]` in `aigenguard.toml` when a safe test or runtime command is detected.
`aigenguard run` intentionally executes the configured command, or an
autodetected command, under best-effort Python runtime instrumentation.

Autodetection prefers simple commands such as:

- `python -m pytest tests/agent_runtime`
- `python -m pytest tests/runbom`
- `python -m pytest`
- npm, pnpm, or bun test scripts when detected

RunBOM prints a human-readable terminal summary and writes machine-readable
artifacts:

```text
AigenGuard RunBOM OK

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

![AigenGuard HTML report preview](docs/assets/html-report-preview.svg)

Generate review artifacts:

```bash
aigenguard scan . --output-dir aigenguard-report --html --mermaid --sarif --pretty
```

Diff-aware scans compare the current report with a baseline JSON report:

```bash
aigenguard scan . --baseline agentbom-baseline.json --fail-on-new high --sarif --html --pretty
```

`--fail-on-new` accepts `low`, `medium`, `high`, or `critical`.

See the [report guide](docs/report-guide.md) for field definitions and reviewer
workflow.

Report filenames remain `agentbom.json`, `agentbom.md`, `agentbom.html`,
`agentbom.mmd`, `agentbom.sarif`, and `agentbom.cdx.json` for compatibility
with existing automation. RunBOM artifacts also remain under `.agentbom/`.

## GitHub Action

Use the action in pull requests to publish reports and a workflow job summary.

```yaml
name: AigenGuard

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

      - name: Run AigenGuard
        uses: vlcak27/aigenguard@v0.8.2
        with:
          path: .
          fail-on: none
          sarif-upload: false
          html: true
          output-dir: aigenguard-report

      - name: Upload AigenGuard reports
        uses: actions/upload-artifact@v4
        with:
          name: aigenguard-report
          path: aigenguard-report/
```

Enable SARIF upload only when you want GitHub code scanning alerts:

```yaml
permissions:
  contents: read
  security-events: write
```

More details: [GitHub Action docs](docs/github-action.md).

New workflows should use `vlcak27/aigenguard@...`. Existing workflows that use
`vlcak27/agentbom@...` need the old action repository and tag to remain
available; do not rely on repository redirects alone for action compatibility.

## Security Model

Static scan and local guard:

- `aigenguard scan` and the local guard are static-only
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
- AigenGuard is AI-agent focused. Use SAST for language-specific vulnerability
  patterns and SBOM tools for package inventory.
- AI/API credential leak checks are focused review signals and are not a
  replacement for full secret scanners such as Gitleaks or TruffleHog.
- Dependency parsing is deterministic and limited, not a full lockfile solver.
- AigenGuard is not an SBOM, SPDX, or CycloneDX replacement.

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
- [Precision](docs/precision.md)
- [Threat model](docs/threat-model.md)
- [Comparison](docs/comparison.md)
- [Agent risk taxonomy](docs/agent-risk-taxonomy.md)
- [Troubleshooting](docs/troubleshooting.md)
- [RunBOM](docs/runbom.md)
