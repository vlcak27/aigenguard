# Configuration review pilot before 0.9.0

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

## Verified quickstart: use a built wheel, not an unpublished release

Build from a reviewed AigenGuard checkout, then use a separate environment:

```bash
python -m build
python -m venv /tmp/aigenguard-pilot-env
/tmp/aigenguard-pilot-env/bin/python -m pip install --no-index --no-deps \
  "$PWD/dist/aigenguard-0.9.0-py3-none-any.whl"
/tmp/aigenguard-pilot-env/bin/aigenguard --version
```

Choose explicit locally available base/head commit SHAs. Review a repository
with a valid policy already present in the base:

```bash
/tmp/aigenguard-pilot-env/bin/aigenguard review --path /path/to/repository \
  --base BASE_SHA --head HEAD_SHA --fail-on medium --output-dir /tmp/review-result
```

`BASE_SHA` and `HEAD_SHA` are placeholders, not implicit trusted choices. Select
the protected branch baseline yourself. If policy is missing, first agree and
commit an appropriate baseline policy, then review later changes. Do not mistake
our comment-only synthetic default policy for an approved operational policy.
Exit 1 means threshold findings in a complete scoped review; exit 2 means it was
not complete. Read separate configuration, original-policy and coverage sections.

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

## Protocol for 3–5 real pilot participants

Recruitment and contact are outside this task; no participants have been contacted
and no responses are claimed. Ask each consenting developer to use one real PR
with a maintainer-approved baseline policy and a pinned scanner release.

1. Record platform, scanner version, base/head SHAs and any install/permission
   blockers. Start the timer at the documented install step.
2. Ask the developer to explain their first result and proposed next action in
   their own words. Record time to that first **understood** result, including
   incomplete results, rather than just time to report generation.
3. For each change, rate usefulness (useful / unclear / irrelevant) and record
   why. Distinguish configured access from verified runtime behavior.
4. Record warning counts, which examples distracted from new changes, and how
   many needed investigation. Credential references are not automatically leaks.
5. Record every incomplete reason and whether its remediation was understandable.
   Do not relax policy or omit files merely to obtain exit 0.

Keep an anonymized table: participant, version/platform, elapsed minutes,
understood result, useful/unclear/irrelevant counts, warning noise, incomplete
reasons, proposed documentation fix. Review 3–5 records qualitatively; do not
turn this small sample into adoption or population-accuracy claims.
