# Changelog

All notable changes to AigenGuard, previously AgentBOM, are documented here.

## Unreleased

### Fixed

- Redact recognizable credentials in review environment names and all public
  scan display fields using the shared static-guard logic; preserve separate
  environment/server comparison identities so masked values do not hide changes.
- Distinguish baseline-policy occurrences by source and evidence, retain known
  secret-finding lines, and show concrete evaluator explanations/remediation.
  Review schema is now 1.1; consumers must rebaseline the corrected event IDs.
- Stream bounded raw Git blobs per snapshot after measured per-blob process
  overhead; preserve read-only snapshots, no filters/fetch, and size checks.

### Evaluation

- Add offline labelled review corpus, pinned provenance for three official
  structures, export/schema invariants, reproducible timing, and required CI.

- Added explicit offline `review --base ... --staged/--head ...` for MCP and TOML
  policy changes using immutable Git objects and the actual index. Existing
  hook behavior and modes are unchanged.
- MCP diffs now detect configuration changes under a stable server name, including
  the documented filesystem server's directory expansion, pin-to-floating package
  selection, endpoints, environment names, and opaque arguments requiring review.
- Review exposes effective policy weakening and independently evaluates candidate
  findings against the base policy. Missing/invalid/unsupported inputs are
  incomplete, not a clean result. JSON/Markdown review schema is versioned.
- Added a real-Git offline demo and an inactive CI example for future 0.9.0;
  opaque arguments, environment values and URL credentials/query values are
  omitted from the new review output. No runtime execution or dependencies added.

## v0.8.5

### Upgrade and Release Reliability

- Status distinguishes legacy, current, damaged, inactive, and foreign hooks.
  Legacy working-tree hooks warn with `aigenguard install-hook`; status never
  changes the hook or index. Current managed blocks have an explicit format version.
- Reinstalling a recognized hook preserves its mode, policy, and executable
  unless explicitly overridden. Repeated installs do not duplicate blocks or
  foreign shell content. Ambiguous/damaged settings require explicit review;
  incomplete or duplicate blocks are refused rather than silently discarded.
- Release validation checks the triggering commit with Ruff, the complete suite,
  precision corpus, wheel/sdist metadata and contents, and an isolated installed
  wheel smoke test of both CLI aliases, scans, and real Git commits. Tag/package
  versions must agree. The publishing job receives only verified artifacts and
  alone has PyPI trusted-publishing permissions; artifacts are not rebuilt there.
- Upgrading the Python package does not update existing hook scripts. Follow
  [the upgrade procedure](docs/policy.md#upgrading-an-existing-installation),
  including staging the intended policy before the first guarded commit.

### Security and Correctness

- Installed pre-commit hooks scan the complete staged Git tree and staged policy,
  including partial staging and deletions, without checkout filters or execution.
  Symlinks and submodules are not followed; missing, symlinked, or oversized staged
  policies fail closed. Manual directory scans retain working-tree behavior.
- RunBOM omits process arguments and lifecycle commands before the first JSONL
  write. Only recognized executable basenames are retained for risk classification.
  Commands resolve through PATH explicitly, including active Windows virtual environments.
- Policy rule files no longer count as model/provider/framework usage evidence;
  secret-value checks remain enabled. Static policy review accepts the separate
  `[runbom]` configuration written by activation.
- Hook installation, status, and removal use Git's effective hooks path. Custom
  paths inside the repository are supported; external or symlink paths are rejected.
  Combining shell hooks preserves foreign content and runs the guard before it.
- Added real Git commit and RunBOM instrumentation regressions. Pinned Ruff and
  its original rule set for reproducible lint; refreshed contributor instructions.

## v0.8.4

### Terminal Output

- Compact product-style CLI scan output.
- Blocked policy-enforced scan output is now limited to two concise lines:
  - `AigenGuard blocked this policy-enforced scan. 1 policy violation needs review.`
  - `Detailed report: open <output-dir>/agentbom.html`
- Pre-commit blocked output is now limited to two concise lines:
  - `AigenGuard blocked this commit. 1 policy violation needs review.`
  - `Detailed report: run with --html to create agentbom.html`
- Successful scan output now reports:
  - `AigenGuard scan completed. No blocking findings found.`
- Advisory scan output now reports:
  - `AigenGuard scan completed with review findings. No blocking enforcement enabled.`
- ANSI color is used for TTY terminal output.
- `NO_COLOR` is supported.
- `--no-color` is supported for `scan` and `guard`.

### Reports and Compatibility

- JSON, Markdown, HTML, and SARIF outputs do not include ANSI escape codes.
- Report filenames remain `agentbom.*`.
- AgentBOM compatibility is preserved.

## v0.8.3

### Documentation

- Documented static precision expectations and false-positive fixture coverage.
- Documented the confidence model and added regression coverage for confidence
  signals.
- Clarified the MCP boundary between inventory and reachable exposure signals.
- Kept wording explicit that AigenGuard does not prove runtime MCP
  reachability, policy safety, exploitability, hosted web reports, full secret
  scanner coverage, or full vulnerability scanning.

### Review Quality

- Added cross-output secret redaction regression coverage for JSON, Markdown,
  HTML, SARIF, CLI, and GitHub summary output.
- Fixed MCP URL credential redaction so credentials embedded in MCP server URLs
  are redacted in reports.
- Added `policy_status` review context for selected findings.
- Added optional SARIF `policy_status` properties when the status is
  unambiguous.
- Improved blocked enforcement output with:
  - `AigenGuard blocked this commit.`
  - a short Top reasons summary
  - a local HTML report pointer to `agentbom.html` when generated

### Compatibility

- AgentBOM compatibility is preserved.
- Report filenames remain `agentbom.*`.

## v0.8.2

### Documentation

- AigenGuard identity polish across the package README and project docs.
- README simplified around the primary workflow: install, activate, commit.
- Public 0.9 credibility roadmap added for positioning, trust, and evaluation work.
- New threat model, comparison, and agent-risk taxonomy docs.
- Docs and examples now prefer `aigenguard-report` as the report output
  directory while preserving existing report filenames.
- Local hook docs and behavior now use AigenGuard managed hook markers while
  preserving old AgentBOM hook marker compatibility.

### Compatibility

- The `agentbom` CLI alias remains available.
- The `agentbom` Python import compatibility path remains available.
- `agentbom.toml` remains supported as a compatibility fallback.
- `agentbom.*` report filenames remain unchanged.
- `.agentbom/` runtime artifacts remain unchanged.
- `AGENTBOM_SKIP_HOOK` remains accepted as a hook bypass alias.

## v0.8.1

### Migration

- AgentBOM is now AigenGuard.
- The `agentbom` CLI and `agentbom.toml` remain supported during migration.
- New projects should use `aigenguard` and `aigenguard.toml`.
- Policy discovery prefers an explicit `--policy` path, then
  `aigenguard.toml`, then the `agentbom.toml` compatibility fallback.
- The PyPI package and Python module are now `aigenguard`.
- The `agentbom` Python package remains as a compatibility import path.
- Report filenames and `.agentbom/` RunBOM artifact paths remain unchanged for
  compatibility with existing automation.

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
