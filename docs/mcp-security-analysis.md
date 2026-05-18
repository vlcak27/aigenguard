# MCP Security Analysis

Model Context Protocol servers can connect an agent runtime to tools outside the
model: local files, shell commands, browsers, databases, cloud APIs, or services
that need credentials. AgentBOM treats MCP configuration as part of the agent
attack surface so reviewers can see which tools are configured and whether they
appear reachable from agent code or prompt context.

Findings are review signals, not exploit verification.

## What AgentBOM Detects

AgentBOM detects common JSON MCP configuration files:

- `mcp.json`
- `.mcp.json`
- `claude_desktop_config.json`
- nested Cursor or Claude MCP config paths such as `.cursor/mcp.json`

For parsed MCP servers, AgentBOM records:

- server name
- source file and confidence
- command
- args
- package or binary name
- transport when visible
- env variable names only, never values
- risk categories
- rationale for the risk category

## Safe Parsing Model

AgentBOM parses MCP configuration as data. It reads JSON MCP config files,
extracts fields, and applies deterministic patterns. It does not execute MCP
servers, does not run configured commands, does not import scanned code, and
does not contact networks. Invalid JSON is handled as a report finding instead
of failing the scan.

The scanner keeps the same repository safety rules used elsewhere in AgentBOM:
large files are skipped, binary-looking files are skipped, and symlink loops are
not followed.

## Secret Handling

AgentBOM records env variable names only. For example, an MCP config containing
`BRAVE_SEARCH_API_KEY` is reported as that name, but the value is not resolved,
stored, or printed. Secret-looking args such as `--token value` are redacted in
output.

## Risk Categories

MCP server risk is assigned with deterministic pattern matching. Categories help
reviewers prioritize access that may matter if the server is enabled and
reachable. They do not verify exploitability.

| Category | Review question |
| --- | --- |
| `filesystem_access` | Can the server read or write local files or directories? |
| `shell_process_execution` | Can the server run commands or spawn processes? |
| `browser_network_access` | Can the server browse, fetch URLs, or search the web? |
| `database_access` | Can the server query databases or data stores? |
| `cloud_access` | Can the server interact with cloud APIs or admin surfaces? |
| `secrets_env_access` | Does the server depend on env-provided credentials? |
| `unknown_custom_server` | Is the server custom or not recognized by simple patterns? |

## Reachability

AgentBOM marks MCP tool invocation as reachable when parsed MCP server config
exists alongside an agent framework or prompt configuration. This is static
evidence of an agent runtime or prompt surface near MCP configuration. The
finding includes the MCP server name, source file, risk categories, and
rationale.

Reachability is an inferred static relationship. It is a review signal. It is
not runtime evidence that a model can call a specific tool in a deployed
environment.

## Policy Controls

The recommended policy format is `agentbom.toml`; use it to allow or deny MCP
server names in the Policy Workbench or by editing `[mcp]` directly.

Legacy YAML policy files are still accepted for compatibility with older MCP
demos. They can deny specific MCP server names or MCP risk categories and can
require controls such as human approval when supported by the legacy parser.

```yaml
deny_mcp_servers:
  - shell-runner

deny_mcp_risk_categories:
  - filesystem_access
  - shell_process_execution
  - secrets_env_access

require:
  human_approval: true
```

Run the legacy policy demo:

```bash
agentbom scan examples/mcp-risky-agent \
  --policy examples/policies/mcp-policy.yaml \
  --output-dir agentbom-report/mcp-policy \
  --html --mermaid --sarif --pretty
```

## Reviewer Checklist

Use this checklist when reviewing MCP findings:

- Confirm whether each MCP server is expected for the repository.
- Check the source config path and server command before trusting the category.
- Treat `shell_process_execution`, `filesystem_access`, `cloud_access`, and
  `database_access` as first-review items.
- Confirm whether env variable names are placeholders, CI-only credentials, or
  production credential references.
- Look for documented controls: sandboxing, read-only mode, allowlists, human
  approval, or least-privilege credentials.
- Review reachable `mcp_tool_invocation` findings next to framework and prompt
  findings.
- Decide whether `agentbom.toml` should allow or deny specific server names.

## Reviewing Findings

Start with high-risk MCP servers, reachable `mcp_tool_invocation`, and policy
findings. Then inspect the config source file to confirm whether the server is
expected and whether policy controls, sandboxing, read-only modes, or human
approval are documented.

## Limitations

AgentBOM does not:

- execute MCP servers
- validate server package authenticity
- contact package registries or remote services
- verify exploitability
- inspect runtime permissions
- trace runtime tool calls
- verify that an env variable exists
- store or print secret values
