# Policy Review

AgentBOM policy review evaluates a local `agentbom.toml` against the scan
result. It is advisory by default: policy violations are reported in CLI,
JSON, Markdown, HTML, and GitHub Actions summary output, but the scan exits
zero unless `--enforce-policy` is used.

AgentBOM remains a static offline scanner. It does not execute scanned code,
import scanned modules, run MCP servers, call networks, add telemetry, or print
secret values.

## Basic Workflow

1. Run a scan with HTML output:

   ```bash
   agentbom scan . --html --pretty
   ```

2. Open `agentbom.html`.
3. Use the Policy Workbench to review detected providers, models, frameworks,
   reachable capabilities, MCP servers, secret references, and policy gaps.
4. Copy or download the generated `agentbom.toml`.
5. Re-run in advisory mode:

   ```bash
   agentbom scan . --policy agentbom.toml --pretty
   ```

6. Enforce only after the policy is stable:

   ```bash
   agentbom scan . --policy agentbom.toml --enforce-policy
   ```

## Format

```toml
[risk]
warn_on = "high"

[providers]
allow = []
deny = []

[models]
allow = []
deny = []

[frameworks]
allow = []
deny = []

[capabilities]
deny = ["shell_execution", "code_execution", "network_access"]

[mcp]
allow_servers = []
deny_servers = []
warn_on_unknown_server = true
require_policy_for_risky_servers = true

[secrets]
warn_on_detected = true

[policy_gaps]
warn_on = "medium"
```

Empty allow lists do not restrict that category. Non-empty allow lists flag
detected values outside the list. Deny lists flag exact normalized names from
the scan output.

Severity thresholds accept `low`, `medium`, `high`, and `critical`.

## GitHub Actions

Use advisory mode first:

```yaml
- name: Run AgentBOM
  uses: vlcak27/agentbom@v0.7.0
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: agentbom.toml
    output-dir: agentbom-report
```

Then opt into policy enforcement:

```yaml
- name: Run AgentBOM
  uses: vlcak27/agentbom@v0.7.0
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: agentbom.toml
    enforce-policy: true
    output-dir: agentbom-report
```

`fail-on` still controls repository risk threshold enforcement. `enforce-policy`
controls only `agentbom.toml` policy violations.
