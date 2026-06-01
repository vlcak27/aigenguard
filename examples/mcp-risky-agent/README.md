# MCP Risky Agent Demo

This static demo contains MCP configuration that should be reviewed. The agent
has a framework and prompt context, plus MCP servers that appear to expose
filesystem, shell/process, browser/network, database, cloud, and env-backed
access. The env entries are variable names only.

AigenGuard scans this directory as text. Do not run the demo agent, install its
requirements, or execute the configured MCP server commands for the scan.

Expected AigenGuard result:

- OpenAI provider and `gpt-4o`
- LangGraph framework
- parsed MCP server metadata from `mcp.json`
- MCP server risk categories
- reachable `mcp_tool_invocation` findings from static framework context
- policy findings because no local policy documentation is present

Run:

```bash
aigenguard scan examples/mcp-risky-agent \
  --output-dir agentbom-report/mcp-risky \
  --html --mermaid --sarif --pretty
```

Review the HTML report:

```bash
open agentbom-report/mcp-risky/agentbom.html
```

Policy example:

```bash
aigenguard scan examples/mcp-risky-agent \
  --policy examples/policies/mcp-policy.yaml \
  --output-dir agentbom-report/mcp-policy \
  --html --mermaid --sarif --pretty
```

Secret handling:

- The code references `OPENAI_API_KEY` by env variable name only.
- `mcp.json` references names such as `BRAVE_SEARCH_API_KEY`,
  `AWS_PROFILE`, and `DATABASE_URL`.
- No secret value is included in this example.
- AigenGuard reports credential names for review and does not store values.
