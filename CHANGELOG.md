# Changelog

All notable changes to AigenGuard, previously AgentBOM, are documented here.

## Unreleased

### Migration

- AgentBOM is now AigenGuard.
- The `agentbom` CLI and `agentbom.toml` remain supported during migration.
- New projects should use `aigenguard` and `aigenguard.toml`.
- Policy discovery prefers an explicit `--policy` path, then
  `aigenguard.toml`, then the `agentbom.toml` compatibility fallback.
- The PyPI package name and Python module remain unchanged for now.

## v0.8.0

### Added

- Guard-first activation presets: `agentbom activate --preset audit`,
  `--preset safe`, and `--preset strict`.
- `safe` is now the default activation preset for newly created
  `agentbom.toml` files.
- Preset policy templates include explicit secret leak policy configuration
  and deterministic, offline AI/API credential leak detection.
- Reports now include `secret_leak_findings` with provider/category, severity,
  confidence, path, line, redacted evidence, and suggested action.

### Improved

- `agentbom activate` now prints the selected preset, guard mode, protected
  policy categories, and next commands for the local pre-commit workflow.
- `agentbom activate --strict` remains compatible as an alias for
  `agentbom activate --preset strict`.
- Local guard terminal output is clearer and uses colored status indicators
  when the terminal supports them.
- README and demo materials have been polished for the v0.8.0 workflow.

### Security Model

- Scanner and guard behavior remain offline-first and deterministic.
- AgentBOM never prints or stores matched secret values; leak findings are
  redacted in JSON, Markdown, HTML, SARIF, CLI output, and GitHub summaries.
- AI/API credential leak checks are not a replacement for full secret scanners
  such as Gitleaks or TruffleHog.
- No runtime dependency changes.

## v0.7.0

### Added

- GitHub Actions job summaries when `GITHUB_STEP_SUMMARY` is available.
- Expanded static model detection for modern OpenAI, Anthropic, Google Gemini,
  DeepSeek, Meta Llama, Mistral, Qwen, xAI Grok, Cohere Command R, and
  Perplexity Sonar identifiers.
- OpenRouter and LiteLLM-prefixed model support, preserving source evidence
  while normalizing the model name for reports and graphs.
- Expanded AI-agent framework detection for AutoGen/AG2, Claude Agent SDK,
  DSPy, Google ADK, Haystack, Instructor, LangServe, LiteLLM, Mastra, OpenAI
  Agents SDK, Pydantic AI, Semantic Kernel, and Vercel AI SDK.
- Deterministic dependency extraction from JavaScript, Rust, and Go manifests,
  including `package.json`, JavaScript lockfiles, `Cargo.toml`, and `go.mod`.

### Improved

- Clearer reachability rationale and mitigation signals for reviewer-facing
  JSON, Markdown, HTML, Mermaid, and SARIF output.
- Clearer Changes since baseline reporting for introduced, resolved, and
  unchanged findings.
- README and report-guide wording aligned around AgentBOM as a static security
  scanner for AI-agent repositories.

### Compatibility

- Output schema documentation now includes reachability mitigations and graph
  node types for prompts and reachable capability nodes.
- No runtime dependency changes.
- Scanner behavior remains offline and deterministic.

## v0.6.0

### Added

- MCP Security Analysis for AI agent attack-surface review.
- Safe JSON-only MCP config parsing for common files such as `mcp.json`,
  `.mcp.json`, `claude_desktop_config.json`, and nested Cursor/Claude paths.
- MCP server metadata extraction for server name, command, args, package or
  binary, transport, source file, confidence, risk categories, and rationale.
- MCP env handling that records variable names only, never values.
- MCP risk categories for filesystem access, shell/process execution,
  browser/network access, database access, cloud access, secrets/env access, and
  unknown/custom servers.
- MCP reachability integration for agent framework or prompt context connected
  to parsed MCP server configuration.
- MCP report coverage across JSON, Markdown, HTML, Mermaid, and SARIF.
- MCP policy support for denied server names and denied risk categories.
- MCP demo repositories for controlled and risky MCP configurations.
- Dedicated MCP Security Analysis documentation guide.

### Security Model

- MCP analysis remains offline and deterministic.
- AgentBOM does not execute MCP servers or scanned code.
- AgentBOM does not contact networks during scanning.
- Secret values and MCP env values are not stored or printed.

### Improved

- Reduced MCP false positives during the pre-release audit, including tighter
  shell/process classification and parsed-server-only MCP reachability.

## v0.5.2

### Improved

- Expanded static model detection coverage for modern OpenAI, Anthropic,
  Google, DeepSeek, local/open, and coding-oriented model identifiers.
- Added support for provider-prefixed and OpenRouter-style model strings such as
  `openrouter/openai/gpt-5.5`, `anthropic/claude-opus-4.7`, and
  `google/gemini-2.5-pro`.
- Updated README and report-guide examples to reflect current static model
  detection coverage.

### Compatibility

- No output schema changes.
- No runtime dependency changes.
- No scanner network behavior changes; scanning remains deterministic and
  offline.

Why this matters: Agent repositories increasingly mix cloud, local, and
router-based model identifiers. This release expands static detection for those
strings.

## v0.5.0

### Added

- HTML reports for offline human review.
- Mermaid capability graph export.
- SARIF export for GitHub code scanning.
- CycloneDX JSON export.
- Repository risk scoring with rationale.
- Reachable capability confidence scoring.
- GitHub Action for CI scanning.

### Improved

- README onboarding, demo workflow, screenshots, and architecture diagrams.
- Report explanations for reviewers.
- Demo repositories for support and research agents.
- Issue templates, release notes templates, and contribution docs.

### Security Model

- Scanner remains offline-first and deterministic.
- Scanner does not execute or import scanned code.
- Secret findings record names only, never values.

## v0.1.0

### Added

- Initial CLI scanner.
- JSON and Markdown reports.
- Provider, model, framework, prompt, MCP, capability, policy, and secret-name
  detection.
- Basic repository risk signals.
