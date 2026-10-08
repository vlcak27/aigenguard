# Review stabilization and first-use guide

This guide targets 0.9.0. Development snapshots use a built wheel; published
installation requires the matching PyPI release.

## First run

From the repository root, install the checkout in your development virtualenv:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
review_demo=$(mktemp -d)/demo
.venv/bin/python scripts/demo_config_review.py --output-dir "$review_demo"
.venv/bin/aigenguard review --path "$review_demo/repository" \
  --base HEAD~3 --head HEAD~2 --fail-on high
```

The last command deliberately exits **1**: the demo's configured filesystem scope
expanded. Read the rule, field, safe before/after, recommendation, and confidence,
not just the exit status. Run the fixed state:

```bash
.venv/bin/aigenguard review --path "$review_demo/repository" \
  --base HEAD~2 --head HEAD --fail-on high
```

This exits 0 and describes narrowing. For your actual repository, select the
intended protected baseline, edit the reported configuration to the minimum
necessary scope, stage the fix with `git add`, and rerun:

```bash
.venv/bin/aigenguard review --base HEAD --staged --fail-on high
```

Exit **2** means incomplete input or an operational error, not a clean review.
Read `coverage.issues`: stage a valid missing policy, repair malformed JSON, or
explicitly account for omitted data. Do not silence the result by weakening the
candidate policy. Candidate violations of the original policy remain visible.

Example of the improved evidence (the model scanner supplies no line):

```text
MEDIUM baseline.models.deny [violation] model.py /models/deny
  Model denied by policy: gpt-4.
  {"rule": "models.deny"} -> {"evidence": "Model denied by policy: gpt-4."}
```

The report recommends removing the model or reviewing the denial. Review does
not automatically edit or approve permission changes. Known secret-finding line
numbers are retained; repeated identical model mentions in one file remain
aggregated by the existing scanner. No invented locations are attached.

## Independent labelled evaluation

```bash
review_eval=$(mktemp -d)/evaluation
.venv/bin/python scripts/review_corpus.py --output-dir "$review_eval" --benchmark
```

The JSON fixtures in `tests/fixtures/review_corpus.json` declare expected rule /
change labels, baseline violations, status and exit **before** evaluation. This
is not the original four-scenario demo reused under new names. Every case uses
a real disposable Git repository. The runner verifies determinism, unique IDs,
JSON/Markdown finding agreement, scan/review schemas, and all seven scan exports
plus review terminal/JSON/Markdown against declared synthetic canaries. A failed
case exits nonzero. Both Python CI jobs run it and upload reports, without
`continue-on-error`. Regular evaluation is entirely offline.

The initial fixture policy accidentally inherited the existing risky-server
requirement, producing unrelated original-policy violations even for unchanged
snapshots. The fixture policy now explicitly disables that unrelated rule to
isolate the labelled deltas; expected labels and production defaults were not
changed. A separate case requires an original-policy violation with *no*
configuration change. Initial failures were not treated as successful results.

Observed labelled results (39 cases, not population precision/recall):

| Control type | Passed / labelled cases |
|---|---:|
| Path semantics | 11 / 11 |
| Execution/package/version | 4 / 4 |
| Identifier changes/redaction | 4 / 4 |
| Policy including unchanged violations | 6 / 6 |
| Invalid/incomplete configuration | 3 / 3 |
| Omitted data / excluded directories | 4 / 4 |
| No-change / normalization invariants | 3 / 3 |
| Staged versus working tree | 1 / 1 |
| Official-structure adaptations | 3 / 3 |

The generated `results.md` contains every scenario, origin, expected/actual
labels, exit, coverage and known limit. `results.json` retains machine-readable
results and timings. Additional pytest regressions cover reversal of comparable
scope, multiple redacted server identities, filenames/policy/endpoint tokens,
same-rule multi-file/multi-model evidence, repeated secret lines, and old metadata.
Neither this small labelled suite nor the existing 18-case precision corpus
establishes accuracy on all real repositories; no precision/recall claim is made.

## Public provenance

`tests/fixtures/review-sources.json` records verified URLs, full commit hashes,
licenses, attribution, date (2026-09-29), and exactly what was adapted:

- [MCP filesystem documentation](https://github.com/modelcontextprotocol/servers/blob/f46d9578190b476b3501923ea8977d899e8db2cb/src/filesystem/README.md): own minimal wrapper for positional directories; synthetic scope mutation. Documentation is CC-BY-4.0; the root license describes a code-license transition.
- [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp/blob/f183dad4a52965583e3cc1d59b88cdc279e2e57d/README.md): standard `mcpServers`/`npx` structure, Apache-2.0. The added opaque option is synthetic, not an assertion about browser permissions.
- [GitHub MCP](https://github.com/github/github-mcp-server/blob/85598ba6e1256f7ebf4867b95d63b833c4549264/README.md): `.vscode/mcp.json` `servers`/HTTP endpoint structure, MIT. The destination change to `example.invalid` is synthetic.

These are our minimal fixtures based on verified structures, not audits of the
upstream products. No upstream code, MCP server, installer, dependencies or real
credentials were executed or bundled. Only the documented supported structures
are evaluated; headers, OAuth and endpoint trust are not inferred.

## Runtime measurements

Measured on macOS 26.6.2 arm64, Python 3.14.5, Git 2.54.0. The benchmark creates
inert, deterministic UTF-8 Python files plus policy/MCP JSON, then measures full
HEAD-versus-index review using `perf_counter`. Repository construction is
excluded; three runs per size, no forced OS-cache flushing. Byte counts exclude
`.git`; individual files remain below 1 MB.

| Files | Bytes | Before median | After median | After samples (s) |
|---|---:|---:|---:|---|
| 22 | 20,744 | 0.201 s | 0.056 s | 0.0569, 0.0553, 0.0555 |
| 1,002 | 1,028,184 | 8.153 s | 0.937 s | 0.9370, 0.9668, 0.9276 |

Measured per-blob Git process startup dominated. The bounded raw-object reader
now uses one `cat-file --batch` process per snapshot, without a cache or execution
of filters. Size is checked before requesting contents and the stream header is
checked again before reading. Existing no-execution/read-only tests still apply.
These are local observations, not a performance guarantee for large monorepos.

## Omitted inputs and readiness

An unrelated oversized tracked file or a symlink yields incomplete / exit 2:
the original policy cannot be verified over omitted content. The reason now
explicitly says that original-policy coverage excludes the entry. A recognized
MCP config under an excluded directory also yields incomplete. Ordinary source
under `node_modules` is outside the existing scanner scope, explicitly listed in
coverage, and does not itself trigger incomplete. That directory is not proven
safe. No omission check was removed to improve the success rate.

The explicit command is suitable for supervised pilots. The native Windows CI
job runs review security tests, both corpora, offline demo and isolated-wheel
validation; release 0.9.0 also includes native staged-guard regressions. Check the
exact release SHA's workflow results rather than inferring support from POSIX
path simulations. Runtime enforcement, client Roots, arbitrary secret recognition
and broad real-world accuracy remain outside verified claims. See
[release evidence](release-0.9.0.md) and the [pilot protocol](review-pilot.md).
