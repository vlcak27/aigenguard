# Customer Support Agent Demo

This static demo repository models a customer support agent that can summarize
tickets, read customer context, and draft responses for human approval.

AigenGuard scans this directory as text. Do not run the demo agent for the scan.

AigenGuard should detect:

- OpenAI provider and `gpt-4o`
- LangChain framework usage
- network and database capabilities
- MCP server metadata and risk categories from `mcp.json`
- prompt surface
- secret references by name only
- policy documentation for controls

Run:

```bash
aigenguard scan examples/customer-support-agent \
  --output-dir aigenguard-report/support \
  --html --mermaid --sarif --pretty
```
