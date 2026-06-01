# GitHub Action

The action runs AigenGuard in GitHub Actions. It writes report artifacts and a
concise job summary with repository risk, detected AI surface, reachable
capabilities, and generated report files. It can also upload SARIF to GitHub
code scanning or fail the workflow when repository risk meets a chosen
threshold.

Policy review is separate from the repository risk threshold. If you provide an
`aigenguard.toml`, AigenGuard evaluates it in advisory mode by default and includes
a short policy result in the job summary. Set `enforce-policy: true` only after
the policy has passed in advisory runs.

## Migration from AgentBOM

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain
supported during migration. New projects should use `aigenguard` and
`aigenguard.toml`.

New workflows should use `vlcak27/aigenguard@...`. Existing workflows that use
`vlcak27/agentbom@...` need the old action repository and tag to remain
available; do not rely on repository redirects alone for action compatibility.

For demos, initial adoption, and repositories with intentional examples, start
with informational mode. This writes JSON/Markdown/HTML reports without failing
CI or creating code scanning alerts. The action defaults are stricter, so set
`fail-on: none` and `sarif-upload: false` explicitly for a non-blocking first
run.

```yaml
name: AigenGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AigenGuard
        uses: vlcak27/aigenguard@v0.8.1
        with:
          path: .
          # Informational mode:
          # publish reports without blocking CI or creating code scanning alerts.
          fail-on: none
          sarif-upload: false
          html: true
          policy: aigenguard.toml
          output-dir: aigenguard-report

      - name: Upload AigenGuard reports
        uses: actions/upload-artifact@v4
        with:
          name: aigenguard-report
          path: aigenguard-report/
```

SARIF upload is optional. Enable it only when you want AigenGuard findings to
appear in GitHub code scanning:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AigenGuard
        uses: vlcak27/aigenguard@v0.8.1
        with:
          path: .
          fail-on: none
          sarif-upload: true
          html: true
          output-dir: aigenguard-report
```

## Modes

Informational mode:

- Set `fail-on: none`.
- Set `sarif-upload: false`.
- Keep `html: true` and upload `aigenguard-report/` as an artifact.
- Review the AigenGuard job summary directly in the workflow run.
- Use this mode to inspect a baseline without failing CI.

SARIF review mode:

- Set `sarif-upload: true`.
- Grant `security-events: write`.
- Keep `fail-on: none` if you want code scanning alerts without blocking CI.

Enforcement mode:

- Set `fail-on: high` or `fail-on: critical` after expected capabilities are
  documented.
- Or set `policy: aigenguard.toml` with `enforce-policy: true` after the policy
  passes in advisory mode.
- Keep report artifacts enabled so reviewers can inspect the reason for a
  failure.
- Make the workflow a required branch protection check only after the threshold
  matches the repository policy.

## Policy Review

Start by generating an HTML report locally or in an informational workflow.
Open `agentbom.html`, use the Policy Workbench to create `aigenguard.toml`, and
commit the reviewed policy.

Advisory workflow:

```yaml
- name: Run AigenGuard
  uses: vlcak27/aigenguard@v0.8.1
  with:
    path: .
    fail-on: none
    sarif-upload: false
    html: true
    policy: aigenguard.toml
    output-dir: aigenguard-report
```

Enforced policy workflow:

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
    output-dir: aigenguard-report
```

AigenGuard remains static and offline in both modes. It does not execute scanned
code, start MCP servers, call networks, or print secret values.
