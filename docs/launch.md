# Public Launch Guide

Use this checklist for public repository setup, screenshots, and announcement
copy.

## GitHub About

Description:

> Offline static scanner for AI-agent components and reachable capabilities.

Website:

> https://pypi.org/project/ai-agentbom/

## GitHub Topics

Recommended topics:

- ai-security
- ai-agents
- agent-security
- mcp
- model-context-protocol
- sbom
- security-tools
- static-analysis
- github-actions
- sarif
- python
- cli

## Screenshot Checklist

Store launch screenshots under `docs/images/`:

- `terminal-quickstart.png`: install command, scan command, and output files.
- `html-report-summary.png`: HTML report header with risk, providers,
  frameworks, and reachable capabilities.
- `mcp-security-analysis.png`: MCP servers, risk categories, source paths, and
  env variable names only.
- `github-action-artifact-mode.png`: passing GitHub Action with report
  artifacts and no code scanning upload.

Use demo repositories from `examples/`. Do not capture private repository names,
private paths, customer data, tokens, or secret values.

## Demo Commands

Install:

```bash
pip install ai-agentbom
```

Quick scan:

```bash
agentbom scan . --pretty
```

Generate reports:

```bash
agentbom scan . --output-dir agentbom-report --html --mermaid --sarif --pretty
```

MCP safe demo:

```bash
agentbom scan examples/mcp-safe-agent --output-dir agentbom-report/mcp-safe --html --mermaid --sarif --pretty
```

MCP risky demo:

```bash
agentbom scan examples/mcp-risky-agent --output-dir agentbom-report/mcp-risky --html --mermaid --sarif --pretty
```

MCP policy demo:

```bash
agentbom scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir agentbom-report/mcp-policy --html --mermaid --sarif --pretty
```

GitHub Action first-run mode:

```yaml
with:
  path: .
  fail-on: none
  sarif-upload: false
  html: true
  output-dir: agentbom-report
```

## Release Notes Template

````markdown
# AgentBOM vX.Y.Z

AgentBOM is an offline static scanner for AI-agent components and reachable
capabilities.

## Highlights

- 

## MCP Security Analysis

- 

## Reports and Integrations

- JSON:
- Markdown:
- HTML:
- Mermaid:
- SARIF:
- GitHub Action:

## Security Model

- Runs offline.
- Does not execute scanned code or MCP servers.
- Records secret names only, never values.
- Findings are review signals, not exploit verification.

## Upgrade

```bash
pip install --upgrade ai-agentbom
```
````

## Launch Copy

X/Twitter:

> AgentBOM is an open-source offline static scanner for AI-agent repositories.
> It maps providers, models, frameworks, prompts, MCP servers, policy gaps, and
> capabilities that appear reachable from an agent. Findings are review signals,
> not exploit verification.

Hacker News:

> AgentBOM is a small open-source CLI that scans AI-agent repositories offline
> and writes JSON, Markdown, HTML, Mermaid, and SARIF reports. v0.8.0 adds
> activation presets, an AI/API secret leak guard with redacted values, clearer
> colored guard terminal output, and README/demo polish.

Reddit:

> I built AgentBOM, an open-source offline scanner for AI-agent repositories. It
> reports providers, model identifiers, frameworks, prompts, MCP configuration,
> reachable capabilities, and policy gaps without executing code or reading
> secret values. v0.8.0 adds activation presets, an AI/API secret leak guard
> with redacted values, clearer colored guard terminal output, and README/demo
> polish.

LinkedIn:

> AgentBOM is an open-source offline static scanner for AI-agent repositories.
> It reports providers, model identifiers, frameworks, prompts, MCP
> configuration, reachable capabilities, and policy gaps. Outputs include JSON,
> Markdown, HTML, Mermaid, SARIF, and a GitHub Action. Findings are review
> signals for human assessment.

## What To Show

- A simple `pip install ai-agentbom` and `agentbom scan . --pretty` flow.
- The HTML report summary.
- MCP server findings with risk categories and source paths.
- Env variable names only, with no secret values.
- Informational GitHub Action mode using `fail-on: none` and
  `sarif-upload: false`.
- SARIF/code scanning as optional, not required for first use.

## What Not To Overclaim

- Do not claim exploit verification or runtime validation.
- Do not claim package authenticity verification.
- Do not claim deep language-specific SAST coverage.
- Do not claim CycloneDX or SPDX replacement.
- Do not claim secret discovery or secret value inspection.
- Do not imply AgentBOM executes MCP servers or contacts networks.
- Do not present deterministic pattern matching as complete vulnerability
  analysis.
