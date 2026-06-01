# Troubleshooting

## aigenguard: command not found

Check that the environment where you installed AigenGuard is active:

```bash
aigenguard --version
```

If the command is still missing, install it from the active environment:

```bash
python -m pip install aigenguard
aigenguard --version
```

If needed, run the `aigenguard` executable from that environment, such as
`.venv/bin/aigenguard` on macOS/Linux or `.\.venv\Scripts\aigenguard.exe` on Windows.
The `agentbom` executable remains available as a compatibility alias.

## macOS / Linux virtualenv activation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install aigenguard
```

## Windows 11 / PowerShell activation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install aigenguard
```

If PowerShell blocks activation, you can choose to allow local user scripts:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Only change execution policy if that matches your workstation policy.

## Activate Says This Is Not a Git Repository

`aigenguard activate` must run inside a Git repository because the guard is
installed under `.git/hooks/pre-commit`.

```bash
cd path/to/your-agent-repo
aigenguard activate
```

## Existing Hook Prevents Activation

Activation fails rather than changing an unrelated pre-commit hook implicitly.
Append the AigenGuard managed block when you want both hooks:

```bash
aigenguard activate --append
```

or use the lower-level hook command:

```bash
aigenguard install-hook --append --policy aigenguard.toml --mode confirm
```

## Status Says Hook Not Installed

Check the current repository:

```bash
aigenguard status
```

If `Local guard: not installed`, run:

```bash
aigenguard activate
```

## Local Guard Cannot Prompt

`confirm` mode needs an interactive terminal. Git hooks may not have normal
stdin, so AigenGuard reads confirmation from `/dev/tty` on POSIX systems.

If no interactive terminal is available, confirm mode fails closed:

```text
aigenguard confirm mode requires an interactive terminal.
Commit blocked. Use advisory mode, enforce mode, or bypass intentionally.
```

Use `advisory` for non-interactive local workflows, or `enforce` when commits
should block without prompting.

## --open does not open the browser

The report is still written. Open the printed HTML path manually, for example:

```text
aigenguard-report/agentbom.html
```

## No HTML report was generated

Use `--html`:

```bash
aigenguard scan . --html
```

You can also use `--open`; AigenGuard writes HTML first when browser opening needs
an HTML report.

## Policy violations do not fail the scan

Policy mode is advisory by default. Use `--enforce-policy` when you are ready for
violations to fail the scan:

```bash
aigenguard scan . --policy aigenguard.toml --enforce-policy
```

## aigenguard.toml already exists

`aigenguard init` will not overwrite an existing policy by default. Write to a new
path or choose to overwrite:

```bash
aigenguard init --output aigenguard-starter.toml
aigenguard init --force
```

## Pre-commit hook cannot find aigenguard

The local hook calls `aigenguard` from `PATH` by default. Install AigenGuard in the
environment used by Git, or reinstall the hook with an explicit command:

```bash
aigenguard activate --aigenguard-command .venv/bin/aigenguard
```

The lower-level hook command accepts the same executable path:

```bash
aigenguard install-hook --policy aigenguard.toml --aigenguard-command .venv/bin/aigenguard
```

The `--agentbom-command` option remains as an alias for compatibility. The hook
remains local to the current repository under `.git/hooks/pre-commit`.

## Bypass local hook

Bypass should be rare, but local hooks can be skipped when needed:

```bash
AIGENGUARD_SKIP_HOOK=1 git commit
git commit --no-verify
```

`AGENTBOM_SKIP_HOOK=1` remains accepted as a compatibility alias.

CI enforcement is better for team-wide guarantees.

Remove the AigenGuard managed hook block:

```bash
aigenguard deactivate
```

## GitHub Action policy path not found

Ensure `aigenguard.toml` is committed and the action scans from the repository
root. Configure the action with:

```yaml
policy: aigenguard.toml
```

## Secret values are not shown

AigenGuard records secret names and references only. Secret values are
intentionally not printed or embedded in reports.

## False positives / missed findings

Static analysis is a review signal. Reachability is inferred from source and
configuration, not runtime proof. Use policy review and the HTML Workbench to
review findings and refine `aigenguard.toml`.
