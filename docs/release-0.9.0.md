# 0.9.0 release evidence

Baseline rechecked on 2026-10-07: main
`394accb7f00b49a085defa1d6b1962c3008c0356`, PRs #47/#48 merged,
source 0.8.5, latest published version 0.8.4. Baseline: 618 pytest tests,
18/18 precision cases, 39/39 labelled review cases. Release availability is
established by the versioned GitHub Release and PyPI, not by this preparation log.

## Regression evidence

- `test_action_shell.py` runs the actual Action shell blocks with the installed
  scanner: ordinary paths, spaces, apostrophes, double quotes, inert command
  substitutions, invalid enums/booleans and preserved failure codes.
- `test_policy_strict.py` checks every static section, private unknown names,
  separate RunBOM, actual scan, real guarded commit with an unstaged policy fix,
  invalid candidate and invalid baseline review.
- `test_review_workflow.py` executes the maintained workflow's object preparation,
  review and summary shell blocks against real Git histories. Cases: unchanged,
  expansion, narrowing, weakened policy plus original-policy violation, 40 old
  credential-reference warnings plus a new high finding, malformed JSON and
  missing baseline. Reports survive exits 1/2. Installed-wheel CI repeats these
  tests from outside the checkout.
- Existing snapshot regressions retain staged/worktree distinction, alternate
  index, symlinks, size limits, collision checks and no execution of filters or
  fsmonitor. No security expectations or failure thresholds were relaxed.

## Staged performance

`python scripts/benchmark_staged.py` builds 500 inert Python files plus one policy:
501 files, 14,813 bytes, all below 1 MB. macOS 26.6.2 arm64, Python 3.14.5;
Git 2.54.0. Three runs on the same machine before/after reusing the existing
bounded raw-object reader. Construction excluded; no cache flushing. Staged scan
includes materialization and `scan_path`; commit includes the actual installed
enforce hook. First commit creates the tree; later commits are allowed empty.

| Run | Before staged scan (s) | After staged scan (s) | Before guarded commit (s) | After guarded commit (s) |
|---|---:|---:|---:|---:|
| 1 | 4.0297 | 0.3100 | 5.3344 | 0.6832 |
| 2 | 4.0454 | 0.3052 | 4.2066 | 0.4003 |
| 3 | 3.9462 | 0.2519 | 4.2220 | 0.3967 |

These observations are not an SLA. The before measurement overlapped baseline
test execution; both include ordinary local scheduling/cache effects. The
architectural change removes one Git process per blob without adding caching.

## Limits and pilot follow-up

Static configuration is not runtime access or exploit proof. Supported argument
interpretation remains narrow; client Roots, wrappers, arbitrary runtime behavior,
unsafe/oversized entries and unsupported formats retain their existing limits.
Unknown static policy keys now fail instead of being ignored. Upgrade hooks
explicitly using `aigenguard install-hook`; compatibility aliases remain.

The [Context7 case study and 3–5-person pilot protocol](review-pilot.md) distinguish
historical changes, synthetic overlays, credential references and incomplete
coverage. No users were contacted, no feedback was invented, and no independent
validation, adoption or uniqueness is claimed.

## Native Windows fixture correction

The first expanded Windows job passed 127 cases but six legacy-hook migration
cases could not construct filenames containing `"` (forbidden by Windows).
The fixture uses an apostrophe on Windows and retains double quotes on POSIX;
both keep spaces, dollar signs and backticks and require the same actual commit
outcomes. No detector rule or enforcement expectation changed. The existing
POSIX executable-bit test is inapplicable on Windows; it remains tested on POSIX.
