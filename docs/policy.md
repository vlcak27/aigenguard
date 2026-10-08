# AigenGuard Policy Review

AigenGuard policy review evaluates a local `aigenguard.toml` against the scan
result. It is advisory by default: policy violations are reported in CLI,
JSON, Markdown, HTML, and GitHub Actions summary output, but the scan exits
zero unless `--enforce-policy` is used.

AigenGuard remains a static offline scanner. It does not execute scanned code,
import scanned modules, run MCP servers, call networks, add telemetry, or print
secret values. Likely AI/API credential leak findings are reported with
redacted metadata only.

## Migration from AgentBOM

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain supported during migration. New projects should use `aigenguard` and `aigenguard.toml`.

Without `--policy`, AigenGuard prefers `aigenguard.toml` and falls back to
`agentbom.toml`. An explicit `--policy` path always wins.

Policy rules are configuration, not evidence that the application uses the listed
models, providers, frameworks, or capabilities. This applies to both compatibility
filenames and an explicitly selected policy. Secret-value inspection still runs
on policy files encountered by the scan. The separate `[runbom]` configuration is
accepted but does not contribute static usage evidence or execute a command.

## Activate AigenGuard in a Repository

From a Git repository root or subdirectory:

```bash
aigenguard activate
```

Activation creates or reuses `aigenguard.toml`, falls back to an existing
`agentbom.toml`, and installs a repo-local
pre-commit hook at Git's effective hook path (normally `.git/hooks/pre-commit`).
It does not modify global Git
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

AigenGuard installs the guard at the path returned by Git, normally
`.git/hooks/pre-commit`. Relative or absolute `core.hooksPath` directories inside
the repository are supported. External custom directories and symlink hook paths
are rejected by installation, status, and removal. A foreign hook is preserved;
use `--append` to combine a shell hook, with AigenGuard running before the foreign
body (including any early `exit`). Non-shell hooks cannot be combined safely.

For a new installation, choose your intended mode and policy, for example:

```bash
aigenguard install-hook --policy aigenguard.toml --mode confirm
```

### Upgrading an existing installation

For the 0.9.0 release, upgrade in the Python environment used by your hook:

```bash
python -m pip install --upgrade 'aigenguard==0.9.0'
aigenguard --version
cd /path/to/your/repository
aigenguard status
aigenguard install-hook
aigenguard status
```

The package upgrade alone does not rewrite existing hook scripts. Run this in
each repository with an installed hook. `install-hook` with no settings preserves
the recognized hook's mode, policy path, and executable, including older AgentBOM
blocks. An explicit option changes only that setting. New installations still
default to advisory mode and `aigenguard.toml`. If the stored executable points
to a different environment, upgrade that environment or deliberately pass
`--aigenguard-command /path/to/the/upgraded/aigenguard`.

Status must report `Local guard: active`, with the intended mode and policy.
A legacy hook warns that it does not verify the staged snapshot. Inactive hooks
can be reinstalled to restore their executable permission. Damaged hooks require
review and explicit `--policy` and `--mode` values; incomplete or duplicate blocks
must be repaired manually first. Status is read-only. A foreign hook requires
`--append` to combine it; only supported shell shebangs can be combined. Updates
retain foreign shell content and place the guard before it.

Before committing, review and stage the exact policy reported by status. For
example, **only when that is your selected path**:

```bash
git add -- aigenguard.toml
git diff --cached -- aigenguard.toml
```

Use your actual policy path in both commands. The staged policy, not an unstaged
edit, controls the commit. A missing staged policy blocks even advisory mode.
Do not run `activate` as an upgrade shortcut: it is a setup command with its own
mode/preset choices. Hook updates respect Git's effective `core.hooksPath`,
including repository-contained relative/absolute paths and default shared Git
hooks in linked worktrees. External custom directories and symlinks remain
unsupported. No command here changes your Git hooks-path setting.

### Modes and staged checks

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

The installed hook adds `--staged` to the guard command:

```bash
aigenguard guard . --policy aigenguard.toml --mode advisory --staged
aigenguard guard . --policy aigenguard.toml --mode confirm --staged
aigenguard guard . --policy aigenguard.toml --mode enforce --staged
```

This reads one fixed tree from the current Git index, including unchanged tracked
files needed for context. Unstaged and untracked files do not affect the result;
staged deletions are absent. Git's temporary index for `git commit --only` is also
honored. Raw blobs are copied to a temporary directory without checkout, smudge,
clean, textconv, fsmonitor, or scanned-code execution. Finding paths stay relative
to the original repository; the temporary directory is removed after scanning.

The selected TOML policy must be a regular staged file inside the repository and
at most 1 MB. Stage it with `git add aigenguard.toml` (or the selected path).
Missing/deleted, symlink, oversized, or invalid staged policies block the guard
even in advisory mode. Working-tree changes to that policy are ignored.
Symlink entries and submodule contents are not followed; ordinary scan exclusions
and size/binary limits still apply. Unmerged indexes and paths that cannot be
represented safely on the host filesystem fail closed. This is a local guard,
not protection against intentional policy weakening or hook bypass.

Without `--staged`, `guard` and `scan` retain directory-scan behavior. Existing
installed blocks must be reinstalled to receive staged scanning.

`aigenguard guard` runs the scan with temporary report output outside the
repository and prints concise commit-time status. Passing policy prints
`AigenGuard OK` in green when stdout is a TTY and `NO_COLOR` is not set; otherwise
it prints plain text.

Terminal output is intentionally concise. Use the local HTML report for detailed
descriptions, evidence, risk, confidence, and policy status.

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
  uses: vlcak27/aigenguard@v0.9.0
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: aigenguard.toml
    output-dir: aigenguard-report
```

Then opt into policy enforcement:

```yaml
- name: Run AigenGuard
  uses: vlcak27/aigenguard@v0.9.0
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: aigenguard.toml
    enforce-policy: true
    output-dir: aigenguard-report
```

`fail-on` still controls repository risk threshold enforcement. `enforce-policy`
controls only `aigenguard.toml` policy violations.

## 0.9.0 strict-key upgrade

Unknown keys inside static sections are errors. For example, `[models]`
`deny_models = ["gpt-4"]` must become `deny = ["gpt-4"]`. Check every policy against
the documented section keys before rollout; unknown names/values are not echoed
in diagnostics. Unknown sections are also rejected. `[runbom]` stays separate.
Invalid policy fails scan and the real staged guard; review marks it incomplete
(exit 2), including when only the candidate has a typo. Severity and threshold
semantics, empty-allowlist behavior, and `agentbom.toml` fallback are unchanged.

Upgrade the package, run `aigenguard status`, then `aigenguard install-hook` and
check status again. Package installation alone does not replace old hooks.
Stage the reviewed policy; the guard uses the index, not an unstaged correction.
