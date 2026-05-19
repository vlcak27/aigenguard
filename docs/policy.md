# Policy Review

AgentBOM policy review evaluates a local `agentbom.toml` against the scan
result. It is advisory by default: policy violations are reported in CLI,
JSON, Markdown, HTML, and GitHub Actions summary output, but the scan exits
zero unless `--enforce-policy` is used.

AgentBOM remains a static offline scanner. It does not execute scanned code,
import scanned modules, run MCP servers, call networks, add telemetry, or print
secret values.

## Activate AgentBOM in a Repository

From a Git repository root or subdirectory:

```bash
agentbom activate
```

Activation creates or reuses `agentbom.toml` and installs a repo-local
pre-commit hook under `.git/hooks/pre-commit`. It does not modify global Git
config. The default guard mode is `confirm`.

Check local setup with:

```bash
agentbom status
```

Modes:

- `advisory` warns but always allows commits.
- `confirm` asks before committing when policy violations exist.
- `enforce` blocks commits when policy violations exist.

Deactivate the local guard with:

```bash
agentbom deactivate
```

Bypass a local hook only when intentional:

```bash
AGENTBOM_SKIP_HOOK=1 git commit
git commit --no-verify
```

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

## Local Guard

AgentBOM can install a repo-local pre-commit guard under
`.git/hooks/pre-commit`:

```bash
agentbom install-hook --policy agentbom.toml --mode confirm
```

Modes:

- `advisory` warns but always allows commits.
- `confirm` asks before committing when policy violations exist.
- `enforce` blocks commits when policy violations exist.

Compatibility:

```bash
agentbom install-hook --policy agentbom.toml --enforce-policy
```

This installs the same behavior as `--mode enforce`. Do not pass
`--mode` and `--enforce-policy` together.

The hook calls the guard command:

```bash
agentbom guard . --policy agentbom.toml --mode advisory
agentbom guard . --policy agentbom.toml --mode confirm
agentbom guard . --policy agentbom.toml --mode enforce
```

`agentbom guard` runs the scan with temporary report output outside the
repository and prints concise commit-time status. Passing policy prints
`agentbom ok` in green when stdout is a TTY and `NO_COLOR` is not set; otherwise
it prints plain text.

Bypass a local hook intentionally with either command:

```bash
AGENTBOM_SKIP_HOOK=1 git commit
git commit --no-verify
```

Remove the repo-local hook block with:

```bash
agentbom deactivate
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
