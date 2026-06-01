# AigenGuard Policy Review

AigenGuard policy review evaluates a local `aigenguard.toml` against the scan
result. It is advisory by default: policy violations are reported in CLI,
JSON, Markdown, HTML, and GitHub Actions summary output, but the scan exits
zero unless `--enforce-policy` is used.

AigenGuard remains a static offline scanner. It does not execute scanned code,
import scanned modules, run MCP servers, call networks, add telemetry, or print
secret values. Likely AI/API credential leak findings are reported with
redacted metadata only.

## Migration from AigenGuard

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain supported during migration. New projects should use `aigenguard` and `aigenguard.toml`.

Without `--policy`, AigenGuard prefers `aigenguard.toml` and falls back to
`agentbom.toml`. An explicit `--policy` path always wins.

## Activate AigenGuard in a Repository

From a Git repository root or subdirectory:

```bash
aigenguard activate
```

Activation creates or reuses `aigenguard.toml`, falls back to an existing
`agentbom.toml`, and installs a repo-local
pre-commit hook under `.git/hooks/pre-commit`. It does not modify global Git
config. The default guard mode is `confirm`. A new policy uses the `safe`
preset by default; an existing `aigenguard.toml` is not overwritten unless
`--force` is passed.

Choose a policy preset when creating or overwriting `aigenguard.toml`:

```bash
aigenguard activate --preset audit
aigenguard activate --preset safe
aigenguard activate --preset strict
```

Presets:

- `audit`: warns only and has no blocking policy defaults.
- `safe`: default local guard preset, including secret leak policy settings.
- `strict`: stricter reachable capability and MCP policy.

Compatibility:

```bash
aigenguard activate --strict
```

This is the same as `aigenguard activate --preset strict`.

Check local setup with:

```bash
aigenguard status
```

Modes:

- `advisory` warns but always allows commits.
- `confirm` asks before committing when policy violations exist.
- `enforce` blocks commits when policy violations exist.

Deactivate the local guard with:

```bash
aigenguard deactivate
```

Bypass a local hook only when intentional:

```bash
AIGENGUARD_SKIP_HOOK=1 git commit
git commit --no-verify
```

## Setup Paths

### 1. Starter policy

Create a safe advisory starter policy:

```bash
aigenguard init
```

Then scan with policy review:

```bash
aigenguard scan . --policy aigenguard.toml --html --open
```

### 2. Suggested policy from findings

Generate a starter policy from the current repository findings:

```bash
aigenguard scan . --suggest-policy aigenguard.toml
```

The suggested policy is meant to start review. It avoids strict provider,
model, and framework allow lists by default.

### 3. Interactive HTML Policy Workbench

Generate and open the offline HTML report:

```bash
aigenguard scan . --html --open
```

Use the Policy Workbench to review detected providers, models, frameworks,
reachable capabilities, MCP servers, secret references, and policy gaps. Copy
or download the generated `aigenguard.toml`.

## Advisory-First Workflow

Start with advisory mode:

```bash
aigenguard scan . --policy aigenguard.toml --pretty
```

Review violations and warnings in CLI, JSON, Markdown, HTML, or GitHub Actions
summary output. Update `aigenguard.toml` until advisory results match
expectations.

Only later add enforcement:

```bash
aigenguard scan . --policy aigenguard.toml --enforce-policy
```

## Local Guard

AigenGuard can install a repo-local pre-commit guard under
`.git/hooks/pre-commit`:

```bash
aigenguard install-hook --policy aigenguard.toml --mode confirm
```

Modes:

- `advisory` warns but always allows commits.
- `confirm` asks before committing when policy violations exist.
- `enforce` blocks commits when policy violations exist.

Compatibility:

```bash
aigenguard install-hook --policy aigenguard.toml --enforce-policy
```

This installs the same behavior as `--mode enforce`. Do not pass
`--mode` and `--enforce-policy` together.

The hook calls the guard command:

```bash
aigenguard guard . --policy aigenguard.toml --mode advisory
aigenguard guard . --policy aigenguard.toml --mode confirm
aigenguard guard . --policy aigenguard.toml --mode enforce
```

`aigenguard guard` runs the scan with temporary report output outside the
repository and prints concise commit-time status. Passing policy prints
`AigenGuard OK` in green when stdout is a TTY and `NO_COLOR` is not set; otherwise
it prints plain text.

Bypass a local hook intentionally with either command:

```bash
AIGENGUARD_SKIP_HOOK=1 git commit
git commit --no-verify
```

`AGENTBOM_SKIP_HOOK=1` remains accepted as a compatibility alias.

Remove the repo-local hook block with:

```bash
aigenguard deactivate
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
block_leaks = true

[policy_gaps]
warn_on = "medium"
```

Empty allow lists do not restrict that category. Non-empty allow lists flag
detected values outside the list. Deny lists flag exact normalized names from
the scan output.

`secrets.warn_on_detected` warns on secret references by name and on redacted
likely AI/API credential leak findings. `secrets.block_leaks` turns likely
credential leak findings into policy violations. If `block_leaks = false`,
leak findings do not block policy enforcement.

Secret leak findings include provider/category, severity, confidence, source
path, line number when available, redacted evidence, and suggested action. The
matched value is not stored or printed in JSON, Markdown, HTML, SARIF, CLI, or
GitHub summary output.

AigenGuard's credential leak checks are AI-agent focused review signals. They are
not a replacement for full secret scanners such as Gitleaks or TruffleHog.

Severity thresholds accept `low`, `medium`, `high`, and `critical`.

## GitHub Actions

Use advisory mode first:

```yaml
- name: Run AigenGuard
  uses: vlcak27/aigenguard@v0.8.1
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: aigenguard.toml
    output-dir: agentbom-report
```

Then opt into policy enforcement:

```yaml
- name: Run AigenGuard
  uses: vlcak27/aigenguard@v0.8.1
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: aigenguard.toml
    enforce-policy: true
    output-dir: agentbom-report
```

`fail-on` still controls repository risk threshold enforcement. `enforce-policy`
controls only `aigenguard.toml` policy violations.
