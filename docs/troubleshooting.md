# Troubleshooting

## agentbom: command not found

Check that the environment where you installed AgentBOM is active:

```bash
agentbom --version
```

If the command is still missing, install it from the active environment:

```bash
python -m pip install ai-agentbom
agentbom --version
```

If needed, run the `agentbom` executable from that environment, such as
`.venv/bin/agentbom` on macOS/Linux or `.\.venv\Scripts\agentbom.exe` on Windows.

## macOS / Linux virtualenv activation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install ai-agentbom
```

## Windows 11 / PowerShell activation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install ai-agentbom
```

If PowerShell blocks activation, you can choose to allow local user scripts:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Only change execution policy if that matches your workstation policy.

## Activate Says This Is Not a Git Repository

`agentbom activate` must run inside a Git repository because the guard is
installed under `.git/hooks/pre-commit`.

```bash
cd path/to/your-agent-repo
agentbom activate
```

## Existing Hook Prevents Activation

Activation fails rather than changing an unrelated pre-commit hook implicitly.
Append the AgentBOM managed block when you want both hooks:

```bash
agentbom activate --append
```

or use the lower-level hook command:

```bash
agentbom install-hook --append --policy agentbom.toml --mode confirm
```

## Status Says Hook Not Installed

Check the current repository:

```bash
agentbom status
```

If `Local guard: not installed`, run:

```bash
agentbom activate
```

## Local Guard Cannot Prompt

`confirm` mode needs an interactive terminal. Git hooks may not have normal
stdin, so AgentBOM reads confirmation from `/dev/tty` on POSIX systems.

If no interactive terminal is available, confirm mode fails closed:

```text
agentbom confirm mode requires an interactive terminal.
Commit blocked. Use advisory mode, enforce mode, or bypass intentionally.
```

Use `advisory` for non-interactive local workflows, or `enforce` when commits
should block without prompting.

## --open does not open the browser

The report is still written. Open the printed HTML path manually, for example:

```text
agentbom-report/agentbom.html
```

## No HTML report was generated

Use `--html`:

```bash
agentbom scan . --html
```

You can also use `--open`; AgentBOM writes HTML first when browser opening needs
an HTML report.

## Policy violations do not fail the scan

Policy mode is advisory by default. Use `--enforce-policy` when you are ready for
violations to fail the scan:

```bash
agentbom scan . --policy agentbom.toml --enforce-policy
```

## agentbom.toml already exists

`agentbom init` will not overwrite an existing policy by default. Write to a new
path or choose to overwrite:

```bash
agentbom init --output agentbom-starter.toml
agentbom init --force
```

## Pre-commit hook cannot find agentbom

The local hook calls `agentbom` from `PATH` by default. Install AgentBOM in the
environment used by Git, or reinstall the hook with an explicit command:

```bash
agentbom activate --agentbom-command .venv/bin/agentbom
```

The lower-level hook command accepts the same executable path:

```bash
agentbom install-hook --policy agentbom.toml --agentbom-command .venv/bin/agentbom
```

The hook remains local to the current repository under `.git/hooks/pre-commit`.

## Bypass local hook

Bypass should be rare, but local hooks can be skipped when needed:

```bash
AGENTBOM_SKIP_HOOK=1 git commit
git commit --no-verify
```

CI enforcement is better for team-wide guarantees.

Remove the AgentBOM managed hook block:

```bash
agentbom deactivate
```

## GitHub Action policy path not found

Ensure `agentbom.toml` is committed and the action scans from the repository
root. Configure the action with:

```yaml
policy: agentbom.toml
```

## Secret values are not shown

AgentBOM records secret names and references only. Secret values are
intentionally not printed or embedded in reports.

## False positives / missed findings

Static analysis is a review signal. Reachability is inferred from source and
configuration, not runtime proof. Use policy review and the HTML Workbench to
review findings and refine `agentbom.toml`.
