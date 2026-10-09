# Demo Workflow

## Configuration review in five minutes

For developers reviewing supported JSON MCP configurations in Git repositories.
This walkthrough uses the **published 0.9.0 package** and the existing release
demo. Python 3.11+, Git, a POSIX shell and network access for installation are
prerequisites. Five minutes is a design goal, not a measured novice-user result.
Nothing below starts an MCP server. Use a fresh empty directory:

```bash
git clone --depth 1 --branch v0.9.0 https://github.com/vlcak27/aigenguard.git tool-source
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: aigenguard==0.9.0
python tool-source/scripts/demo_config_review.py --output-dir demo
cd demo/repository
aigenguard review --base HEAD --staged --fail-on high
```

The trusted release checkout supplies only the demo script, which is not included
in the installed package; the scanner comes from PyPI, not an editable checkout.
The script creates a disposable repository and an explicit **demo-only** policy.
It exercises formatting, expansion, weakening and narrowing with exits 0/1/1/0.
Its final state has `/workspace/project` configured and a committed policy.
The last command above prints:

```text
AigenGuard review: complete; 0 change/review finding(s).
```

Exit 0 means complete within supported scope and below the requested threshold;
it is not a claim that the project or server is safe.

Expand the configured directory and stage it:

```bash
python -c 'import json,pathlib; p=pathlib.Path(".mcp.json"); d=json.loads(p.read_text()); d["mcpServers"]["files"]["args"][-1]="/"; p.write_text(json.dumps(d))'
git add .mcp.json
aigenguard review --base HEAD --staged --fail-on high
```

Actual published-package output (followed by a generated report directory):

```text
AigenGuard review: complete; 1 change/review finding(s).
HIGH mcp.filesystem_scope [expanded] .mcp.json /mcpServers/files/args
  Configured filesystem directory scope broadened. Client Roots can override it; symlinks and actual runtime access are not evaluated.
  ["posix:/workspace/project"] -> ["posix:/"]
```

Expected exit **1**. The file and JSON field identify the change: startup directory
scope now covers `/`. Inspect `aigenguard-review.md` in the printed report directory
for the recommendation. Narrow it back to the intended project directory:

```bash
python -c 'import json,pathlib; p=pathlib.Path(".mcp.json"); d=json.loads(p.read_text()); d["mcpServers"]["files"]["args"][-1]="/workspace/project"; p.write_text(json.dumps(d))'
aigenguard review --base HEAD --staged --fail-on high
git add .mcp.json
aigenguard review --base HEAD --staged --fail-on high
```

Before `git add`, review still returns **1**: correcting only the working copy
does not change the commit candidate. After staging the correction, it returns
**0** with `complete; 0 change/review finding(s).` Manual `scan .` examines the
working tree; review `--staged` and the local guard examine the index.

These expected nonzero exits are interactive checks. Do not put the walkthrough
under `set -e` without explicitly handling them.

## Use your own project

A base commit must already contain a maintainer-approved `aigenguard.toml` (or
compatible `agentbom.toml`). If it does not, review exits **2**, even after you
stage a new candidate policy. Run `aigenguard init` to draft one, review its rules
with the maintainer, and commit it through normal review on the intended base
branch. Only then compare later changes against that commit. Empty allowlists
are unrestricted; the demo policy is not a production recommendation.

For the everyday local guard, use `aigenguard activate`, inspect the policy,
stage it, and commit. See [policy setup](policy.md) and the
[maintained PR workflow](config-review.md#ci-integration-and-limits).

Configured scope is not runtime reachability or exploit proof. Client Roots,
symlinks, unsupported argument wrappers and actual server behavior are not
verified. Missing policy and omitted/unsupported input stay incomplete; do not
weaken policy or suppress coverage to get a green result. RunBOM is a separate,
optional execution workflow, not part of this demo.

For optional HTML/Mermaid inventory reports from release-checkout examples, see
[report guide](report-guide.md). For transparent simulations and the pilot
invitation, see [pilot notes](review-pilot.md#published-package-first-use-simulations).
