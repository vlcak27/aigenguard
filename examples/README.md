# AigenGuard Examples

These directories are static demo repositories for trying AigenGuard. They are not
intended to be executed.

## customer-support-agent

A controlled support automation example with an OpenAI/LangChain agent, a CRM
API call, local ticket lookup, MCP configuration, prompt instructions, and a
policy file. Use it to inspect findings with documented controls. Its
`mcp.json` is also a minimal MCP Security Analysis example: AigenGuard records the
server command and the `CRM_BASE_URL` env variable name without storing the
value.

```bash
aigenguard scan examples/customer-support-agent \
  --output-dir agentbom-report/support \
  --html --mermaid --sarif --pretty
```

## mcp-safe-agent

A controlled MCP example with a local memory server, prompt context, and human
approval policy documentation. Use it to inspect MCP review signals with
documented controls.

```bash
aigenguard scan examples/mcp-safe-agent \
  --output-dir agentbom-report/mcp-safe \
  --html --mermaid --sarif --pretty
```

## mcp-risky-agent

An MCP-focused example with filesystem, shell/process, browser/network,
database, cloud, and env-backed server configuration. Values are placeholders;
AigenGuard records env variable names only. Use it to inspect reachable MCP tool
invocation and policy findings.

```bash
aigenguard scan examples/mcp-risky-agent \
  --output-dir agentbom-report/mcp-risky \
  --html --mermaid --sarif --pretty

aigenguard scan examples/mcp-risky-agent \
  --policy examples/policies/mcp-policy.yaml \
  --output-dir agentbom-report/mcp-policy \
  --html --mermaid --sarif --pretty
```

## research-agent

An intentionally risky research automation example with a CrewAI/Anthropic
agent, prompt instructions, network access, and shell execution without policy
documentation. Use it to inspect review priorities and SARIF output.

```bash
aigenguard scan examples/research-agent \
  --output-dir agentbom-report/research \
  --html --mermaid --sarif --pretty
```
