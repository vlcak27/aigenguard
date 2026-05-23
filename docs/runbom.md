# RunBOM

RunBOM is AgentBOM's optional experimental runtime evidence mode. It runs a
configured or autodetected command and records best-effort Python runtime
activity while the command runs.

RunBOM is optional. It is not a sandbox, does not enforce policy yet, and is not
part of the local pre-commit guard. `agentbom scan` and pre-commit remain
static-only.

## Quickstart

```bash
agentbom activate
agentbom run
```

`agentbom activate` installs the static local guard and, when possible, adds a
`[runbom]` section to `agentbom.toml`. `agentbom run` executes the configured
command, or an autodetected command, under experimental Python runtime
instrumentation.

To set a command directly:

```bash
agentbom activate --command "python -m pytest"
agentbom run
```

## Command Autodetection

RunBOM detects simple test/runtime commands without executing project code
during detection. It prefers:

- `python -m pytest tests/agent_runtime` when `tests/agent_runtime/` exists
- `python -m pytest tests/runbom` when `tests/runbom/` exists
- `python -m pytest` when pytest project signals are present
- `pnpm test`, `bun test`, or `npm test` when a package test script is detected

If `agentbom.toml` already has an enabled `[runbom]` command, that configured
command is used.

## Terminal Summary

RunBOM prints a human-readable developer summary after the command finishes:

```text
AgentBOM RunBOM OK

Runtime summary:
  153 events observed
  57 unique events
  Highest risk: high

Top runtime signals:
  HIGH env.read OPENAI_API_KEY
       Why: agent read an AI provider credential variable name.
       Note: secret value was not recorded.

  HIGH filesystem.read .env
       Why: agent read a common local secrets file.
       Fix: avoid reading local secrets files during agent runtime checks unless expected.

Artifacts:
  .agentbom/runbom-summary.json
  .agentbom/runbom.jsonl
```

Terminal output shows the developer summary and at most the top runtime
signals. High-risk runtime evidence does not fail the command by itself.

## Artifacts

RunBOM writes artifacts under `.agentbom/`:

- `runbom-summary.json`: machine-readable summary with observed events, unique
  events, highest risk, risk counts, event type counts, and risky events
- `runbom.jsonl`: raw normalized runtime events, one JSON object per line

## Event Types

RunBOM currently records these Python runtime events:

- `filesystem.read`
- `filesystem.write`
- `process.exec`
- `network.connect`
- `env.read`

Lifecycle events such as `run.start` and `run.end` are also written to the JSONL
log.

## Risk Classification

Each event is normalized and tagged with a risk level. Risk levels are `low`,
`medium`, `high`, and `critical`.

High or critical examples include reads from `.env`, Git config, or SSH paths;
writes to GitHub workflow files; reads of secret-like environment variable
names; shell or network-tool process execution; private network connections;
and metadata service access.

Risk classification is review guidance. It does not prove exploitability, block
the command, or enforce policy.

## What Is Never Recorded

RunBOM records environment variable names, command shapes, paths, hosts, ports,
and event metadata. It does not record secret values. Secret-looking command
arguments are redacted before they are written.

## Limitations

- Experimental and best-effort.
- Python-focused instrumentation via runtime hooks.
- Not a sandbox.
- Does not enforce policy yet.
- High-risk evidence is advisory and does not fail the command by itself.
- Does not cover all library, native extension, subprocess, or non-Python
  behavior.
- Executes the configured or autodetected command, so use commands you trust.

## Troubleshooting

If no command is detected, create a dedicated runtime test directory and
activate again:

```bash
mkdir -p tests/agent_runtime
agentbom activate
agentbom run
```

Or configure a direct command:

```bash
agentbom activate --command "python -m pytest"
agentbom run
```

If RunBOM finds high-risk evidence, inspect the terminal Why/Fix guidance first,
then review `.agentbom/runbom-summary.json` for the machine-readable summary and
`.agentbom/runbom.jsonl` for raw events. Secret values are not recorded in either
artifact.
