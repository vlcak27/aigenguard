# AigenGuard Roadmap

AigenGuard has the core public adoption surface in place: PyPI package, HTML
reports, Mermaid export, SARIF integration, CycloneDX export, GitHub Action,
realistic examples, and onboarding documentation.

The roadmap below is intentionally conservative. AigenGuard should remain
offline-first, deterministic, dependency-light, and safe to run on untrusted
repositories.

## Migration

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain supported during migration. New projects should use `aigenguard` and `aigenguard.toml`.

## Current Focus

- Keep MCP Security Analysis precise, explainable, and easy to review.
- Keep detector accuracy improvements offline and deterministic.
- Keep report outputs stable and easy to diff.
- Make CI adoption simple without requiring hosted services.

## v0.6.0 MCP Security Analysis

Status: implemented.

- Detect common MCP JSON config files, including `mcp.json`, `.mcp.json`,
  `claude_desktop_config.json`, and nested Cursor/Claude paths.
- Parse MCP server definitions safely without code execution or network access.
- Extract server name, command, args, transport, package or binary, and env
  variable names only.
- Classify MCP server risk across filesystem, shell/process, browser/network,
  database, cloud, secrets/env, and unknown/custom categories.
- Connect MCP server config to reachable `mcp_tool_invocation` findings when an
  agent framework or prompt configuration is present.
- Include MCP security analysis in JSON, Markdown, HTML, Mermaid, and SARIF.
- Support simple custom policy denies for MCP server names and risk categories.

## Near-Term Candidates

- More package and configuration parsing with standard-library parsers where
  possible.
- More precise framework-to-tool registration patterns.
- Policy allowlists for expected capabilities.
- Baseline comparison for existing repositories.
- Additional SARIF rule help and remediation text.
- More demo repositories that mirror real agent architectures.

## Not Yet Planned

- SPDX export.
- Dynamic analysis.
- Runtime tracing.
- Telemetry.
- Hosted scanning.
- LLM-generated findings.

## Release Principles

- New findings should include source paths and confidence.
- New outputs should be deterministic.
- New dependencies should be avoided unless they are clearly justified.
- Secret values must never be stored or printed.
