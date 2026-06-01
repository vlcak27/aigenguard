# MCP Safe Agent Demo

This static demo contains a controlled MCP setup. The agent has a prompt, a
LangChain model call, a local memory MCP server, and policy text that requires
human approval before tool output is used.

AigenGuard scans this directory as text. Do not run the demo agent or install its
requirements for the scan.

Expected AigenGuard result:

- OpenAI provider and `gpt-4o`
- LangChain framework
- parsed MCP server metadata from `.mcp.json`
- `unknown_custom_server` MCP category for the local memory server
- reachable `mcp_tool_invocation` with documented controls

Run:

```bash
aigenguard scan examples/mcp-safe-agent \
  --output-dir aigenguard-report/mcp-safe \
  --html --mermaid --sarif --pretty
```

Review the HTML report:

```bash
open aigenguard-report/mcp-safe/agentbom.html
```

Secret handling:

- The code references `OPENAI_API_KEY` by env variable name only.
- No secret value is included in this example.
- AigenGuard reports credential names for review and does not store values.
