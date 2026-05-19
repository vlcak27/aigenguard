# Policy Review

AgentBOM policy review evaluates a local `agentbom.toml` against the scan
result. It is advisory by default: policy violations are reported in CLI,
JSON, Markdown, HTML, and GitHub Actions summary output, but the scan exits
zero unless `--enforce-policy` is used.

AgentBOM remains a static offline scanner. It does not execute scanned code,
import scanned modules, run MCP servers, call networks, add telemetry, or print
secret values.

## Setup Paths

### 1. Starter policy

Create a safe advisory starter policy:

```bash
agentbom init
```

Then scan with policy review:

```bash
agentbom scan . --policy agentbom.toml --html --open
```

### 2. Suggested policy from findings

Generate a starter policy from the current repository findings:

```bash
agentbom scan . --suggest-policy agentbom.toml
```

The suggested policy is meant to start review. It avoids strict provider,
model, and framework allow lists by default.

### 3. Interactive HTML Policy Workbench

Generate and open the offline HTML report:

```bash
agentbom scan . --html --open
```

Use the Policy Workbench to review detected providers, models, frameworks,
reachable capabilities, MCP servers, secret references, and policy gaps. Copy
or download the generated `agentbom.toml`.

## Advisory-First Workflow

Start with advisory mode:

```bash
agentbom scan . --policy agentbom.toml --pretty
```

Review violations and warnings in CLI, JSON, Markdown, HTML, or GitHub Actions
summary output. Update `agentbom.toml` until advisory results match
expectations.

Only later add enforcement:

```bash
agentbom scan . --policy agentbom.toml --enforce-policy
```

## Local Git Guard

AgentBOM can install an opt-in local `pre-commit` hook without the external
`pre-commit` framework:

```bash
agentbom install-hook --policy agentbom.toml
```

The hook runs from the git repository root, checks that the policy file exists,
and scans into a temporary output directory that is removed when the hook exits.
It does not leave `agentbom.json` or `agentbom.md` in the repository during
normal commits.

Advisory mode is the default. Policy violations are printed but do not block
commits unless scanning itself fails or the hook is misconfigured. After review,
install the enforced guard:

```bash
agentbom install-hook --policy agentbom.toml --enforce-policy
```

If `.git/hooks/pre-commit` already exists and is not managed by AgentBOM, the
installer leaves it untouched. Use `--append` to add the AgentBOM managed block
to an existing shell hook, or `--force` to replace the existing hook.

Remove the managed block later with:

```bash
agentbom uninstall-hook
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
