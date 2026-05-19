# Report Guide

AgentBOM reports are designed for mixed engineering, security, and governance
reviews. The scanner does not execute code and does not claim exploitability.
It records static evidence, source paths, confidence, and rationale.

## Read order

1. Repository risk: a compact severity and score with rationale.
2. Review priorities: the shortest queue of findings to triage first.
3. Reachable capabilities: AI actors connected to sensitive actions.
4. Policy findings: controls that appear missing or violated.
5. Policy review: the result of an optional `agentbom.toml` policy evaluation.
6. Component sections: providers, models, frameworks, MCP security analysis,
   prompts, dependencies, secret references, and secret leak findings.
7. Policy Workbench: an HTML-only builder for creating `agentbom.toml` from
   the current scan findings.

## Terms

- Provider: AI service or runtime vendor such as OpenAI, Anthropic, or Gemini.
- Model: concrete model identifier found by static pattern matching, such as
  `gpt-5.1`, `claude-sonnet-4.6`, `gemini-3.1-pro`,
  `llama-3.3-70b-instruct`, `command-r-plus`, `sonar-pro`, or
  `openrouter/openai/gpt-5.1`.
- Framework: agent orchestration library such as LangChain or CrewAI.
- MCP server: a Model Context Protocol server definition found in JSON config.
  AgentBOM records server metadata and env variable names only.
- MCP risk category: deterministic classification for server definitions that
  appear to expose filesystem, shell/process, browser/network, database, cloud,
  secrets/env, or unknown/custom capabilities.
- Capability: static evidence of a sensitive action, such as shell or network.
- Reachable capability: an inferred relationship from an AI actor to a
  capability.
- Policy finding: a missing control or custom policy violation.
- Policy review: advisory or enforced evaluation of `agentbom.toml`. Advisory
  review never fails the scan by itself.
- Secret leak finding: a likely AI/API credential value detected by static
  pattern matching. Values are always redacted.

## Model evidence

Model findings separate the normalized model name from the source evidence. For
example, `openrouter/openai/gpt-5.1` is stored as the model name `gpt-5.1`, while
the evidence field keeps the provider-prefixed string seen in the scanned file.
This keeps graphs and summaries grouped by model while preserving the exact text
reviewers need to inspect.

Provider-prefixed strings are common in router and proxy configurations. A value
such as `openrouter/anthropic/claude-sonnet-4.6` is static evidence of the model
identifier and route style; it is not proof that the repository can reach that
provider at runtime.

## MCP security analysis

The MCP Security Analysis section lists each detected MCP config file or parsed
server definition. AgentBOM currently parses JSON only, including `mcp.json`,
`.mcp.json`, `claude_desktop_config.json`, and common nested Cursor or Claude
paths. Invalid JSON is reported as a low-confidence review signal instead of
failing the scan.

For parsed servers, review:

- `command`, `args`, `transport`, and `package`: how the MCP server appears to
  launch or connect.
- `env`: variable names only. Values are not stored or printed.
- `risk_categories`: why the server may matter for attack-surface review.
- `rationale`: the simple pattern match that caused the category.

If an agent framework or prompt configuration exists with an MCP config,
AgentBOM adds reachable `mcp_tool_invocation` entries. Those entries identify
the MCP server, risk categories, and rationale so reviewers can decide whether
the tool exposure is expected, sandboxed, or policy-approved.

AgentBOM TOML policy can deny MCP server names:

```toml
[mcp]
deny_servers = ["filesystem"]
```

## What to do with findings

For expected capabilities, document the control in policy files and keep the
source path easy to review. For unexpected capabilities, remove the code path,
isolate it behind a sandbox or approval boundary, or make the repository policy
explicit about why it exists.

Secret reference findings require credential hygiene review only. AgentBOM
records names such as `OPENAI_API_KEY`.

Secret leak findings indicate likely AI/API credential values for providers
such as OpenAI, Anthropic, Google/Gemini, Cohere, Hugging Face, GitHub, and
generic `API_KEY`, `TOKEN`, `SECRET`, `ACCESS_KEY`, or `PRIVATE_KEY`
assignments. The report includes only redacted metadata: provider/category,
severity, confidence, source path, line number when available, redacted
evidence, and suggested action. It must not store or print matched secret
values in JSON, Markdown, HTML, SARIF, CLI output, GitHub summaries, or tests.

These checks remain offline, static, deterministic, and AI-agent focused. They
are not a replacement for full secret scanners such as Gitleaks or TruffleHog.

## Policy Workbench

The HTML report always includes a Policy Workbench. It lists detected providers,
model identifiers, frameworks, reachable capabilities, MCP servers, secret
reference names, and policy gaps from the current scan. Choose allow, deny,
warn, or ignore for each item, then copy or download the generated
`agentbom.toml`.

The builder runs offline with inline JavaScript only. It does not make network
calls and does not include secret values.

Run the generated policy in advisory mode first:

```bash
agentbom scan . --policy agentbom.toml --pretty
```

Only use enforcement once expected findings are reviewed:

```bash
agentbom scan . --policy agentbom.toml --enforce-policy
```
