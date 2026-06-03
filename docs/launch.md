# Public Launch Guide

Use this checklist for public repository setup, screenshots, and announcement
copy.

## GitHub About

Description:

> Local-first pre-commit policy guard for AI-agent repositories.

Website:

> https://pypi.org/project/aigenguard/

## GitHub Topics

Recommended topics:

- ai-security
- ai-agents
- agent-security
- mcp
- model-context-protocol
- pre-commit
- policy-as-code
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
pip install aigenguard
```

Quick scan:

```bash
aigenguard scan . --pretty
```

Generate reports:

```bash
aigenguard scan . --output-dir aigenguard-report --html --mermaid --sarif --pretty
```

MCP safe demo:

```bash
aigenguard scan examples/mcp-safe-agent --output-dir aigenguard-report/mcp-safe --html --mermaid --sarif --pretty
```

MCP risky demo:

```bash
aigenguard scan examples/mcp-risky-agent --output-dir aigenguard-report/mcp-risky --html --mermaid --sarif --pretty
```

MCP policy demo:

```bash
aigenguard scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir aigenguard-report/mcp-policy --html --mermaid --sarif --pretty
```

GitHub Action first-run mode:

```yaml
with:
  path: .
  fail-on: none
  sarif-upload: false
  html: true
  output-dir: aigenguard-report
```

## Release Notes Template

````markdown
# AigenGuard vX.Y.Z

AigenGuard is a local-first pre-commit policy guard for AI-agent repositories.

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
pip install --upgrade aigenguard
```
````

## Launch Copy

X/Twitter:

> AigenGuard is an open-source local-first pre-commit policy guard for AI-agent
> repositories. It gives deterministic review signals for risky agent
> capabilities, MCP exposure, policy gaps, and AI/API credential context before
> changes land in git.

Hacker News:

> AigenGuard is a small open-source CLI for local pre-commit policy review in
> AI-agent repositories. It installs a repo-local guard, keeps static scanning
> offline and deterministic, and reports risky capabilities, MCP exposure,
> policy gaps, and AI/API credential context without executing scanned code.

Reddit:

> I built AigenGuard, an open-source local-first pre-commit policy guard for
> AI-agent repositories. It reports risky capabilities, MCP exposure, policy
> gaps, and AI/API credential context without executing scanned code, importing
> scanned modules, or sending code to network services.

LinkedIn:

> AigenGuard is an open-source local-first pre-commit policy guard for AI-agent
> repositories. It helps teams catch risky agent capabilities, MCP exposure,
> policy gaps, and AI/API credential context before changes land in git.
> Findings are deterministic review signals for human assessment.

## What To Show

- A simple `pip install aigenguard` and `aigenguard scan . --pretty` flow.
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
- Do not position AigenGuard as a generic MCP scanner.
- Do not position AigenGuard as a cloud security platform.
- Do not position RunBOM as the main product.
- Do not imply AigenGuard executes MCP servers or contacts networks.
- Do not present deterministic pattern matching as complete vulnerability
  analysis.
