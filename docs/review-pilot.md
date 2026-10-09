# Configuration review pilot

Automated pilot conducted 2026-09-30, finalized 2026-10-06. This is **not feedback
from real users**, nor a random sample or a population accuracy estimate. PR #47
was verified merged into main `ccc9c26ee6c042e2ffcf33af1a869de3361f0f91` before work.

## Sources and independently specified expectations

The exact base/head SHAs, paths, selection rationale and expected rule labels are
in [review-pilot.json](../tests/fixtures/review-pilot.json). All selected snapshots
actually contain supported configuration, not only README examples.

| Repository | Base → head | Why selected / historical expectation |
|---|---|---|
| [getsentry/sentry-mcp](https://github.com/getsentry/sentry-mcp/commit/94e20f3046d85e99e7ef560cd7bc2d8531e55b0c) | `d20bc1a51caee75f5196e1d3e925742ae22b6343` → `94e20f3046d85e99e7ef560cd7bc2d8531e55b0c` | Mixed npx and HTTP servers, three client layouts. Two Cursor transport fields removed, one Claude endpoint query changed, one local server removed: four changes. |
| [upstash/context7](https://github.com/upstash/context7/commit/d812afe2f85aa39257bc31cd2fe2904f13bd9b63) | `1d8b25a9e7234bddcc7131411cd788830922ee88` → `d812afe2f85aa39257bc31cd2fe2904f13bd9b63` | Remote service and plugin variants. Removal of headersHelper: one opaque configuration review, not an inferred OAuth permission change. |
| [github/github-mcp-server](https://github.com/github/github-mcp-server/commit/59847fb6204b276dcdbe10eaf14ebe3a73176948) | `a014a187c125d883968baf88b4ba1fb1c70052b1` → `59847fb6204b276dcdbe10eaf14ebe3a73176948` | New schema-annotated Agent Plugins package: one remote server added. |

Expectations were set by reading raw JSON changes and Git tree metadata before
running review. Only Git objects were fetched; no upstream checkout, imports,
installers, dependencies, scripts or MCP servers were executed. No upstream
credentials were used. Inputs above 1 MB were identified by metadata, not read.

## Actual wheel onboarding and results

`scripts/pilot_review.py` creates a clean venv, installs the local built wheel
with `--no-index --no-deps`, verifies its import path is inside that venv, and
invokes the installed CLI from a trusted temporary working directory. It does
not import the source-checkout scanner. The receipt records the wheel SHA-256.

Each repository has three separately labelled runs:

1. **Historical native**: exactly the upstream base/head objects.
2. **Historical + synthetic policy**: same upstream data, with the same explicitly
   synthetic default policy added to both trees as local overlay commits.
3. **Synthetic endpoint**: synthetic-policy head versus a controlled replacement
   of one URL with `https://pilot-destination.example.invalid/mcp`.

No overlays are upstream commits or approvals. Default policy behavior was not
relaxed. Whole trees were reviewed; no repository-specific exclusions were added.

| Repository / tracked head files | Native history | History + synthetic policy | Synthetic endpoint | Observed seconds (three runs respectively) |
|---|---|---|---|---|
| Sentry / 637 | 4/4 changes; incomplete, exit 2 | 4/4; incomplete, exit 2 | 1/1; incomplete, exit 2 | 3.205 / 3.198 / 3.227 |
| Context7 / 503 | 1/1; incomplete, exit 2 | 1/1; incomplete, exit 2 | 1/1; incomplete, exit 2 | 2.007 / 1.991 / 1.984 |
| GitHub / 580 | 1/1; incomplete, exit 2 | 1/1; complete, exit 1 | 1/1; complete, exit 1 | 3.526 / 3.451 / 3.488 |

Times include installed CLI startup and complete review, not fetching, installation
or overlay construction; one observation per scenario, macOS arm64 / Python 3.14.5.
All nine scenario expectations matched. There were no unexpected or missed
**labelled supported configuration deltas**: six unique historical changes and
three controlled changes. This does not establish precision/recall for arbitrary
code or audit all other findings.

### Practical friction, unsupported cases, and noise

- **3/3 repositories lack AigenGuard policy**. Native onboarding always exits 2;
  simply adding policy in the candidate does not supply a missing base policy.
- Sentry has three symlinks, seven oversized entries, two unsupported flat plugin
  maps and an unrelated metadata document named `mcp.json`. The latter is a
  filename-based coverage false alarm, not a newly introduced permission or
  vulnerability. Its ambiguity remains explicit; no filename exception was added.
- Context7 has one unsupported flat Cursor plugin map. Its supported Claude
  configuration is still compared, but the whole-tree result remains incomplete.
- Synthetic default-policy runs produce **186 / 130 / 105 baseline warnings**
  respectively, all under `secrets.warn_on_detected`. These include existing
  credential *references*, not demonstrated secret leaks or new config changes.
  This is substantial onboarding noise. The individual warnings were not all
  manually adjudicated; do not report them as confirmed vulnerabilities or zero
  false positives. No warning rule was weakened to make the pilot green.
- Query-only endpoint changes show masked before/after labels that may look the
  same. The finding correctly remains visible; reviewers must inspect the
  original trusted diff for omitted details. Helper removal remains opaque.
- Seven of nine whole-tree runs are incomplete; only GitHub with synthetic policy
  reaches complete analysis. Exit 2 takes precedence over risk exit 1.

## Published-package quickstart

For first use, follow the [published-package demo](demo-workflow.md). In your own
fresh virtual environment, install `python -m pip install aigenguard==0.9.0`.
The historical automated pilot below used locally built wheels; it is separate
from the published-package simulations at the end of this page.

Choose explicit locally available base/head commit SHAs. Review a repository
with a valid policy already present in the base:

```bash
aigenguard review --path /path/to/repository \
  --base BASE_SHA --head HEAD_SHA --fail-on medium --output-dir /tmp/review-result
```

`BASE_SHA` and `HEAD_SHA` are placeholders, not implicit trusted choices. Select
the protected branch baseline yourself. If policy is missing, first agree and
commit an appropriate baseline policy, then review later changes. Do not mistake
our comment-only synthetic default policy for an approved operational policy.
Exit 1 means threshold findings in a complete scoped review; exit 2 means it was
not complete. Read separate configuration, original-policy and coverage sections.

For contributor reproduction of the historical pilot, use a trusted source
checkout with development dependencies and a built wheel (`python -m build`).
This is separate from the published-package first-use path above.

The exact automated reproduction below tests installation and concrete SHA
selection without editing upstream working trees. Fetch only pinned Git objects
into new local repositories (no checkout or upstream scripts):

```bash
pilot_sources=$(mktemp -d)
python - "$pilot_sources" <<'PY'
import json, pathlib, subprocess, sys
manifest = json.loads(pathlib.Path('tests/fixtures/review-pilot.json').read_text())
for case in manifest['repositories']:
    repo = pathlib.Path(sys.argv[1]) / case['id']
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'core.hooksPath=/dev/null',
                    '-c', 'maintenance.auto=false', 'fetch', '--depth=1',
                    case['url'] + '.git', case['base'], case['head']], check=True)
PY
python scripts/pilot_review.py --repos "$pilot_sources" \
  --wheel dist/aigenguard-0.9.0-py3-none-any.whl \
  --output-dir "$(mktemp -d)/pilot-results"
```

The fetch step needs network; the pilot runner is offline. Existing user
repositories are not modified. On Windows use `Scripts\python.exe` and
`Scripts\aigenguard.exe` in the clean venv; the CI workflow exercises native
review rather than claiming POSIX runs prove Windows support.

## Native Windows and release gate

The first Windows run passed 82 security/review tests and failed the actual demo:
it looked beside python.exe instead of Python's Scripts directory. Fixed with
`sysconfig.get_path('scripts')` and a dedicated regression, without skipping tests.
The Windows job also runs both corpora, the demo and installed-wheel validation.
Symlink privilege or runner limitations must remain failures/incomplete evidence,
not blanket security skips. Its final status is recorded in the PR.

`scripts/review_corpus.py` is now a required step in the **release validate job**,
before build/artifact upload; publication depends on that job. It is not merely
an unrelated optional CI check.

## Release follow-through and remaining limits

0.9.0 retains the schema 1.1 identities and explicit whole-tree incomplete
behavior. Baseline onboarding and grouped warnings are documented and exercised
by the maintained PR workflow tests. Release requires native Windows and
installed-wheel integration checks on the exact commit, followed by the existing
validated-artifact publishing pipeline. See [release evidence](release-0.9.0.md).
Actual pilot-user feedback remains future work under the protocol below.
Supported configuration explanations are demonstrated; frictionless onboarding
and broad runtime/security accuracy are not established.

## Short case study: Context7 configuration review

Historical input: [base 1d8b25a9](https://github.com/upstash/context7/commit/1d8b25a9e7234bddcc7131411cd788830922ee88)
to [head d812afe2](https://github.com/upstash/context7/commit/d812afe2f85aa39257bc31cd2fe2904f13bd9b63),
with complete SHAs and changed paths retained in the pilot manifest above.
The historical change removed `headersHelper`. Review reported one opaque
configuration change requiring review; it did not infer an OAuth permission grant.
The native result was incomplete (exit 2): no baseline AigenGuard policy and an
unsupported flat Cursor plugin map. Adding the explicitly synthetic policy
still left unsupported coverage and produced 130 credential-reference warnings,
not 130 confirmed leaks. The separate synthetic endpoint mutation was detected
but is not an upstream historical event. These are the recorded pre-release
pilot results, not newly collected user feedback or independent validation.

For 0.9.0, grouped warnings make the change visible while complete JSON evidence
and incomplete status remain. The next action is to inspect the helper removal,
agree and commit a real baseline policy, and resolve unsupported coverage before
relying on a complete result. No upstream endorsement is implied.

## Invitation for the first three pilot participants

> Would you try AigenGuard 0.9.0 on the short disposable MCP configuration demo,
> then, if it fits your work, one real configuration change? It reviews configured
> permissions and the original policy; it does not prove runtime safety. Please
> follow the linked walkthrough without assistance first, note where you get
> stuck, and stop rather than weakening policy to make it pass. We are evaluating
> whether the result and next action are useful, not asking for an endorsement.
> Share sanitized notes only; do not send credentials or private source files.

Send the [walkthrough](demo-workflow.md), [coverage and PR workflow](config-review.md),
and these five questions. No one has been contacted; no feedback is claimed.

1. What did the first finding mean in your own words, and what did you do next?
2. How long from starting installation to understanding a result, and what
   setup, manual edits or help did you need? Include platform and version.
3. Which output was confusing or unnecessarily noisy? Distinguish existing
   credential references from new configuration changes.
4. Did you encounter exit 2/incomplete? Which reason appeared, and was the next
   step clear? If not, what information was missing?
5. Would you leave the tool enabled in your normal commit/PR workflow? Why or
   why not, and what would need to change?

Use one record per consenting participant. Record unsuccessful attempts too;
three responses are qualitative pilot input, not adoption or accuracy evidence.

## Published-package first-use simulations

On 2026-10-08, an experienced automated operator ran **three simulations**, not
user research, against published `aigenguard==0.9.0`. Public documentation baseline:
[release/main 151a9b0](https://github.com/vlcak27/aigenguard/tree/151a9b034f781b9d218b4b8bacebb89a5ec25a2e),
PR #49 merged; release and PyPI installation verified. This exercise reuses the
existing demo and workflow; it is not another security audit.

Each scenario used a new venv and synthetic Git project on macOS arm64 / Python
3.14.5. Installation used PyPI, never editable source. Fixture setup deliberately
set a synthetic Git author, disabled inherited system/global Git configuration,
removed inherited Git/PYTHONPATH overrides, and put that venv's `bin` on PATH.
These are declared test-isolation conditions, not undocumented troubleshooting
steps taken to repair an onboarding failure. Network was needed only for install.
Default pip cache was allowed. No MCP server or scanned program was executed.

| Simulation | Observed result | Automated elapsed seconds |
|---|---|---:|
| New small project, no policy | missing base/candidate: exit 2; after `init` + stage: still 2; after deliberately reviewed policy commit: 0 | 6.197 |
| Existing project, 40 old reference warnings | unchanged 0; expansion 1 with HIGH first; staged correction 0; all 40 warnings retained in JSON | 5.669 |
| PR workflow, local emulation | Git preparation 0; review 1; summary 0; JSON/Markdown and local summary present | 6.422 |

Times include venv/install, fixture construction and commands, measured by
`perf_counter` in the automation. They exclude documentation reading, human
interpretation and approval delays. They are **not novice onboarding times**.
No hidden environment repair was needed during the runs.

### What required manual judgment or clearer instructions

1. **Published-package entry point:** README still described 0.9.0 as pending;
   first-use pages led to editable installs or local builds and assumed possession
   of the release demo script. A fresh package environment contains the scanner,
   not `scripts/demo_config_review.py`. The revised walkthrough explicitly obtains
   the trusted tagged script, installs the published wheel and runs the full
   baseline → expansion → fix sequence. No scanner code changed.
2. **Missing base policy:** the short evaluation guide suggested staging missing
   policy. Executing that advice left `INCOMPLETE base: aigenguard.toml: policy is
   missing` and exit 2. The detailed review guide already explained the correct
   process; the short guide now distinguishes candidate and base. The operator
   must review actual restrictions, commit approved baseline policy through normal
   review and only then compare later changes. No automatic permissive baseline.

No third blocker was manufactured. Existing warnings were verbose in terminal
output, but the new HIGH appeared first and Markdown grouped all 40 warnings.
The operator still needed to open the printed Markdown report for recommendations.
The corrected configuration produced exit 0 at `--fail-on high` while the medium
warnings remained; this is threshold behavior, not suppression or a clean bill
of health. Different thresholds can legitimately fail on those warnings.

### PR integration: local evidence and missing external step

The operator copied the maintained workflow into the synthetic project's
`.github/workflows/config-review.yml`, committed it on the base, made a candidate
scope expansion, and emulated two depth-1 checkouts. The **unchanged public shell
blocks** prepared Git objects, ran the published scanner and appended the summary.
The fixture contains explicit base/head commits and a pre-approved demo policy.

This was **not a new GitHub Actions run**. It does not verify hosted checkout,
fork approval, artifact upload/download, job-summary UI or required-check settings.
The release's actual [installed-wheel CI](https://github.com/vlcak27/aigenguard/actions/runs/37757638957)
is prior evidence for the integration test, not a pilot user's PR deployment.

For that final end-to-end check, a maintainer must select a disposable GitHub
repository with Actions enabled, push the prepared base (reviewed policy and
workflow), and open the prepared expansion branch as a PR targeting `main`.
Expected: failed review job with exit 1, readable summary and downloadable
`configuration-review` artifact; after the scoped fix, exit 0. Protect the
workflow/check according to the repository's review rules. Do not install PR
code or switch to `pull_request_target`. No external repository was created or
participant contacted in this exercise.

### Synthetic fixture and actual command record

The setup wrote `.mcp.json` with the same filesystem-server form as the existing
demo: `npx`, arguments `-y`, `@modelcontextprotocol/server-filesystem`,
`/workspace/project`. Expansion replaces only the last argument with `/`; the
fix replaces it back. The deliberately reviewed **demo-only**, not production,
policy was:

```toml
[mcp]
allow_servers=["files"]
[secrets]
block_leaks=true
[models]
deny=["gpt-4o"]
```

The existing-project fixture also wrote `client_0.py` through `client_39.py`, each
containing `import os` and `key = os.getenv("OPENAI_API_KEY")`; these are references,
not credentials. The new-project fixture began without policy. After `init`, the
operator explicitly replaced its draft with the above reviewed demo policy and
committed it; this manual content choice was not an automatic tool action.

Below are the actual executed argument vectors rendered as shell commands.
Machine-specific scratch prefix is normalized to `$SIM`; commands are grouped
by working directory. Venv PATH is selected per scenario. The three `.sh` files
contain, unchanged, the correspondingly named shell blocks in the
[release workflow](https://github.com/vlcak27/aigenguard/blob/v0.9.0/examples/config-review/github-actions.yml).

<details>
<summary>new: executed commands and exits</summary>

```bash
cd "$SIM/new"
python3 -m venv $SIM/new/venv  # exit 0
$SIM/new/venv/bin/python -m pip install --only-binary=:all: aigenguard==0.9.0  # exit 0
aigenguard --version  # exit 0
cd "$SIM/new/project"
git init -b main  # exit 0
git config user.name 'Synthetic pilot'  # exit 0
git config user.email pilot@example.invalid  # exit 0
git add .  # exit 0
git commit -m 'Explicit synthetic baseline'  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/new/missing  # exit 2
aigenguard init  # exit 0
git add aigenguard.toml  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/new/only-staged  # exit 2
git add aigenguard.toml  # exit 0
git commit -m 'Approve demo-only baseline policy'  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/new/complete  # exit 0
```

</details>

<details>
<summary>existing: executed commands and exits</summary>

```bash
cd "$SIM/existing"
python3 -m venv $SIM/existing/venv  # exit 0
$SIM/existing/venv/bin/python -m pip install --only-binary=:all: aigenguard==0.9.0  # exit 0
aigenguard --version  # exit 0
cd "$SIM/existing/project"
git init -b main  # exit 0
git config user.name 'Synthetic pilot'  # exit 0
git config user.email pilot@example.invalid  # exit 0
git add .  # exit 0
git commit -m 'Explicit synthetic baseline'  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/existing/before  # exit 0
git add .mcp.json  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/existing/expanded  # exit 1
git add .mcp.json  # exit 0
aigenguard review --base HEAD --staged --fail-on high --output-dir $SIM/existing/fixed  # exit 0
```

</details>

<details>
<summary>pr: executed commands and exits</summary>

```bash
cd "$SIM/pr"
python3 -m venv $SIM/pr/venv  # exit 0
$SIM/pr/venv/bin/python -m pip install --only-binary=:all: aigenguard==0.9.0  # exit 0
aigenguard --version  # exit 0
cd "$SIM/pr/project"
git init -b main  # exit 0
git config user.name 'Synthetic pilot'  # exit 0
git config user.email pilot@example.invalid  # exit 0
git add .  # exit 0
git commit -m 'Explicit synthetic baseline'  # exit 0
git add .github  # exit 0
git commit -m 'Approve published scanner workflow'  # exit 0
git rev-parse HEAD  # exit 0
git checkout -b expand  # exit 0
git add .mcp.json  # exit 0
git commit -m 'Synthetic permission expansion'  # exit 0
git rev-parse HEAD  # exit 0
cd "$SIM/pr"
git clone --depth 1 --branch main file://$SIM/pr/project $SIM/pr/workspace/review-base  # exit 0
git clone --depth 1 --branch expand file://$SIM/pr/project $SIM/pr/workspace/review-head  # exit 0
cd "$SIM/pr/runtime"
bash --noprofile --norc -eo pipefail $SIM/pr/Prepare-Git-objects-explicitly.sh  # exit 0
bash --noprofile --norc -eo pipefail $SIM/pr/Review-Git-data-with-explicit-SHAs.sh  # exit 1
bash --noprofile --norc -eo pipefail $SIM/pr/Job-summary.sh  # exit 0
```

</details>

Local workflow environment (event SHAs were explicit fixture commits):

```text
BASE_SHA=10b80ea494d535308540bc5e9c845d6cf5aac371
HEAD_SHA=bbf2e9b0a199953a8a007043749fb66379cada83
GITHUB_WORKSPACE=$SIM/pr/workspace
RUNNER_TEMP=$SIM/pr/runtime
GITHUB_STEP_SUMMARY=$SIM/pr/runtime/summary.md
```

Actual excerpts from the published scanner:

```text
AigenGuard review: incomplete; 0 change/review finding(s).
INCOMPLETE base: aigenguard.toml: policy is missing
AigenGuard review: complete; 41 change/review finding(s).
HIGH mcp.filesystem_scope [expanded] .mcp.json /mcpServers/files/args
  Configured filesystem directory scope broadened. Client Roots can override it; symlinks and actual runtime access are not evaluated.
  ["posix:/workspace/project"] -> ["posix:/"]
```

The revised walkthrough was also executed in a fourth fresh environment using
the published wheel and tagged demo script. Its interactive review exits were
0 (baseline), 1 (expansion), 1 (unstaged fix), 0 (staged fix). This validates
the instructions, not novice understanding.
