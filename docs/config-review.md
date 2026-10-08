# Configuration security review (0.9.0)

The explicit offline command in 0.9.0 does not install, update, or change hooks.
For development snapshots use a built wheel; the pinned CI example requires the
0.9.0 package to be published and approved by your maintainers.

```bash
aigenguard review --base HEAD --staged
aigenguard review --base BASE_COMMIT_SHA --head HEAD_COMMIT_SHA --fail-on high
```

Both forms write `aigenguard-review.json` and `aigenguard-review.md` to a new
temporary directory outside the checkout and print its location. Use
`--output-dir /path/to/reports` for a chosen destination, and `--path /path/to/repo`
to select a repository. An explicitly chosen output directory can of course
create report files there; source files and Git state are never edited.

## What is compared

- The base must be a locally available commit. A revision is validated and resolved
  to a concrete commit and tree before any analysis. Replace objects are disabled.
- `--head` resolves a second commit; uncommitted files cannot affect either state.
- `--staged` captures the complete index entry manifest, including unchanged files,
  and then reads those immutable blob IDs. `GIT_INDEX_FILE` is honored. The report
  identifies the index by a SHA-256 manifest digest, **not** a Git tree object ID.
  No index refresh or `write-tree` is needed, and the original index is not written.
- Git object reads disable fsmonitor, lazy fetching, and network protocols. No Git
  filters, textconv, external diff, scanned code, or MCP server is executed.
- On an initial repository without HEAD, `--base HEAD` returns exit 2 with an
  unavailable-base error. There is no implicit empty/trusted policy. Supply an
  existing explicit baseline commit when your workflow has one.

## Supported configuration and evidence

The existing MCP parser and scanner are reused. JSON files named `.mcp.json`,
`mcp.json`, and `claude_desktop_config.json` are supported, including nested
locations such as `.cursor/mcp.json` and `.vscode/mcp.json`. Recognized containers
are `mcpServers`, `mcp_servers`, and `servers`, either top-level or nested under
`mcp`, `modelContextProtocol`, or `model_context_protocol`.

Dictionary server names are identities within a file/container. Named list entries
are matched by `name`/`id`; unnamed entries use their positions. Named list
reordering is ignored, but reports retain the actual candidate JSON Pointer for
the changed field. Renames are deliberately reported as removal plus addition,
with safe configuration summaries, rather than guessed matches that could hide
changes. Duplicate JSON keys and duplicate list identities are incomplete input.

The report separates:

1. MCP configuration changes: server additions/removals, executable or npm package,
   package version, fixed-to-floating package selection, directory scope,
   remote endpoint, environment **names**, and otherwise opaque arguments/options.
2. TOML policy changes: rules normalized with the actual scanner defaults and
   evaluator semantics, not a text diff.
3. Candidate findings evaluated under the **base** policy, even when the candidate
   removes, invalidates, or relaxes its own policy.

The underlying `scan --baseline ... --fail-on-new high` path also receives these
MCP security deltas through `diff_reports`; the same-name/same-file directory
expansion now creates an introduced high finding. Existing diff fields remain,
with an additive `security_changes` list. Existing MCP findings gain optional
versioned `security_config`, `config_pointer`, and `config_identity` fields.
Older reports without configuration metadata still support comparisons of their
recorded fields, but carry an explicit incomplete-coverage finding; rescan both
snapshots before relying on endpoint/opaque-option comparisons.

## Deliberately narrow argument interpretation

Directory interpretation is limited to the documented filesystem reference server:

- `npx` / `npx.cmd`, optionally `-y` or `--yes`, followed by the exact npm package
  `@modelcontextprotocol/server-filesystem` (optionally with a version), followed
  only by directory arguments;
- direct `mcp-server-filesystem` followed only by directory arguments.

The [official filesystem server documentation](https://github.com/modelcontextprotocol/servers/blob/main/src/filesystem/README.md)
was checked on 2026-09-29: positional arguments configure allowed directories,
but MCP client Roots can replace them dynamically. This review describes the
**configured startup scope**, not an enforced runtime boundary or an exploit.
Wrappers such as `cmd /c`, Docker, `npm exec`, and arbitrary custom executables
are not interpreted as filesystem grants in this iteration.

Containment is compared by normalized path components, never string prefix:
`/project` and `/project2` are unrelated. Absolute POSIX, absolute Windows drive/
UNC, and relative path families are kept distinct. Relative containment is a
lexical relationship under the same hypothetical working directory, not a
resolution to the review machine. Parent traversal, drive-relative paths,
variables, tilde expansion, and ambiguous roots require review; no directory is
read and no environment variable is expanded. Windows path case is not folded;
cross-drive, cross-platform, and incomparable scopes require review. Symlink
resolution and client working-directory behavior remain unverified.

Directory argument sets and environment names are order-insensitive. General
argument order is preserved. Launcher-option changes require review separately.
Unknown arguments/options are compared opaquely and reported as
`review_required`, never assigned invented permissions. Empty filesystem argument
sets may depend on client Roots and are not treated as zero access.

## Policy semantics and baseline selection

Discovery prefers root `aigenguard.toml`, then `agentbom.toml`. Use
`--policy security/custom.toml` for a specific repository-relative path in both
snapshots. Unsafe or unscannable preferred policies do not silently fall back.

Empty allowlists mean **no allowlist restriction**; deny takes precedence.
For named rules, the combined allow/deny sets determine effective access. For
example, removing a denial of `b` while an allowlist still permits only `a` has
`no_effect`. Capability aliases and list ordering are normalized according to
the existing evaluator. Disabling `secrets.block_leaks` or
`mcp.require_policy_for_risky_servers` is visible as weakening. Raising a risk
threshold or disabling warning controls is distinguished from strengthening.
Unknown static section keys, unsupported policy sections and invalid types are incomplete, not successful.
`[runbom]` settings are not static enforcement rules and are outside this review.

Base-policy evaluation uses the existing scanner's candidate findings and
repository-policy evidence semantics. Thus it remains a static signal, not an
independent execution permission system. Missing or invalid **base** policy means
that evaluation was not performed, even if the candidate has a valid policy.

A base commit is not automatically trustworthy. The caller selects it. In CI,
maintainers should select the protected target branch's base SHA and protect the
review workflow and required checks. A contributor-selected base can already
contain weakened policy. This command does not approve policy changes or add a
cryptographic approval system.

## Results, completeness, and exit codes

Review JSON schema `1.1` is documented in [review-schema.json](review-schema.json).
Findings carry a stable rule ID, deterministic event ID, component, file, field
pointer, safe before/after values, explanation, severity, recommendation, and
separate change/impact confidence. Classifications are `added`, `removed`,
`expanded`, `narrowed`, `review_required`, `no_effect`, `incomplete`, and `violation`.
Configuration change confidence does not establish impact confidence.

Schema 1.1 corrects occurrence IDs: the digest includes the relative file,
available evaluator evidence/location, and pre-display comparison identity.
`rule_id` remains the rule category; `id` distinguishes occurrences, including
different models in one file and secret findings on different known lines.
IDs are deterministic within this contract, not compatible with the defective
1.0 IDs. Consumers should rebaseline event IDs when upgrading. Model inventory
aggregates repeated instances of the same model in one file and provides no
line; review does not fabricate finer locations. Baseline findings now retain
the evaluator's concrete safe explanation and remediation instead of generic
"base rule / candidate finding" text.

| Exit | Meaning |
|---|---|
| 0 | Complete within documented scope; no requested `--fail-on` threshold exceeded. Findings may still require review. |
| 1 | Complete, with a risk/review finding at or above `--fail-on`. |
| 2 | Invalid invocation, operational error, or incomplete analysis, regardless of threshold. |

Without `--fail-on`, findings remain advisory but incomplete input still exits 2.
Narrowing, removal, and no-effect findings are informational and do not trip a
threshold. Policy removal/invalidity always makes the analysis incomplete.

Malformed/unsupported JSON, duplicate identities, missing/invalid policy, unmerged
indexes, unavailable Git objects, unsafe paths, symlinks/submodules and oversized
inputs prevent a complete result. Files larger than 1 MB and binary files are not
read as configuration; omitted entries are surfaced rather than interpreted as
clean configuration. Non-JSON MCP files with conventional names are explicitly
unsupported. Other non-JSON integrations are outside coverage. The scanner's
existing source exclusions and static detection limitations still apply.

Opaque argument values and environment values are never copied into review
reports. Remote endpoints show only scheme/host/port; userinfo, path, query and
fragment are omitted. Unrecognized executable/package/version values are omitted.
Opaque SHA-256 digests in scanner metadata permit deterministic comparisons;
they are not encryption or evidence that arbitrary data can be safely shared.
Selected directory paths and valid environment variable **names** remain review
evidence, with recognizable credential patterns and terminal controls redacted.
Parser errors do not echo raw input. Markdown escapes untrusted identifiers.

Recognizable credentials embedded in env names, server/file identifiers, policy
values and endpoint hosts use the shared static-guard redactor. Ordinary names
such as `OPENAI_API_KEY` remain visible. Internal raw snapshot evidence is used
only for policy evaluation; public scan results are redacted before exporters
receive them. Separate environment/server identity digests keep two redacted
values from collapsing into an unchanged item. Hashes are not anonymization and
regexes cannot recognize arbitrary secrets. Old metadata without these identity
fields has explicitly limited comparison coverage; rescan both sides.

See [first-use instructions and reproducible evaluation](review-evaluation.md)
for corpus provenance, measurements, omissions, and pilot readiness.

## Reproduce the offline demo

From this checkout with development dependencies already installed:

```bash
python scripts/demo_config_review.py --output-dir /tmp/aigenguard-config-review-demo
```

Choose a new output directory each time. The script creates a disposable Git
repository, five commits, actual CLI reviews, JSON/Markdown reports, and
`results.json` / `results.md` with the exact compared SHAs. It does not fetch or
start an MCP server. Repeat an individual comparison using those SHAs:

```bash
aigenguard review --path /tmp/aigenguard-config-review-demo/repository \
  --base BASE_SHA_FROM_RESULTS --head HEAD_SHA_FROM_RESULTS --fail-on high
```

Observed on the implementation's real-Git demo:

| Scenario | Expected | Actual | Exit |
|---|---|---|---|
| A: formatting only | no security change | no security change | 0 |
| B: project directory → `/` | expanded filesystem scope | expanded, high | 1 |
| C: expansion + remove model denial + add denied model | both changes and original-policy violation | expanded scope, weakened policy, original-policy violation | 1 |
| D: `/` → project directory | narrowing | narrowed, low | 0 |

This is a regression/demo corpus, not a claim of precision across real projects.

## CI integration and limits

[The maintained workflow](../examples/config-review/github-actions.yml) can be copied
to `.github/workflows/config-review.yml` after the pinned **0.9.0** wheel is published. It installs the trusted wheel before
checking out PR data, compares explicit base/head SHAs outside the PR directory,
and publishes summary/artifacts without commenting on the PR. It never installs
PR dependencies, imports PR code, or runs PR scripts. Adapt the protected base
branch and exact approved scanner version. CI executes the same shell blocks
against seven real-Git scenarios using an installed wheel. The review step keeps
its failure status while `always()` uploads reports and appends the summary.
Warnings are grouped by rule/severity with three examples; full evidence and
identities remain in JSON, and threshold decisions are unchanged.

A local hook is not protection against a computer owner who intentionally
bypasses it. Static review does not replace a runtime sandbox. This iteration
does not evaluate MCP client Roots, resolve external paths or symlinks, verify
package authenticity, infer arbitrary arguments, or fix configurations for users.
