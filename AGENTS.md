# AGENTS.md

## Project

AigenGuard is a local-first pre-commit policy guard for AI-agent repositories,
with offline static inventory and reports. Optional experimental RunBOM runs an
explicitly configured or autodetected command for best-effort runtime evidence.

AgentBOM has been renamed to AigenGuard. Keep the `agentbom` CLI compatibility
alias and `agentbom.toml` compatibility fallback. New projects should use
`aigenguard` and `aigenguard.toml`.

## Rules for coding agents

- Keep code simple.
- Do not add runtime dependencies unless asked.
- Static scans and pre-commit must never execute or import scanned code, Git
  filters, or repository-configured fsmonitor programs. RunBOM is an explicit,
  separate runtime workflow and must not run from pre-commit.
- Do not read files larger than 1 MB.
- Do not scan binary files.
- Do not follow symlink loops.
- Never store or print secret values in reports, logs, or terminal output.
- Test secret handling only with synthetic canaries.
- Pre-commit must scan the full Git index and its staged policy. Manual directory
  scans continue to inspect the working tree. Preserve original finding paths.
- Never commit .env files.
- The scanner must work offline.
- Prefer simple pattern matching and standard-library parsing; no large refactors.
- Preserve existing JSON, Markdown, HTML, Mermaid, SARIF, and CycloneDX output,
  `agentbom.*` report names, `.agentbom/` runtime artifacts, and compatibility aliases.
- Use the pinned development Ruff and explicit `E4`, `E7`, `E9`, `F` rule set in
  `pyproject.toml`. Do not inherit newly expanded default rules or blanket-ignore errors.
- Hook tests must use real Git repositories and verify actual commit outcomes.

## Commands

Install:

pip install -e ".[dev]"

Validate (Git must be on PATH):

python -m ruff check .
python -m pytest
python scripts/precision_corpus.py
python -m build

Install the built wheel in a fresh virtual environment and smoke-test both
`aigenguard` and `agentbom`. Do not change the package version or publish as part
of a correctness fix.

Run:

aigenguard scan examples/simple_agent --pretty
