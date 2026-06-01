# Contributing to AigenGuard

AigenGuard is intentionally small, deterministic, and offline-first. Contributions
should preserve that shape.

AgentBOM has been renamed to AigenGuard. Keep the `agentbom` CLI alias and
`agentbom.toml` config fallback working while new code and docs use
`aigenguard` and `aigenguard.toml`.

## Development Setup

```bash
pip install -e ".[dev]"
```

Run the local checks:

```bash
ruff check .
pytest
```

You can also use the Make targets:

```bash
make check
make demo
```

## Design Rules

- Do not execute scanned code.
- Do not import scanned modules.
- Do not add runtime dependencies unless the tradeoff is clear and documented.
- Do not read files larger than 1 MB.
- Do not scan binary files.
- Do not follow symlink loops.
- Do not store or print secret values.
- Keep output deterministic for the same input repository.

## Good First Contributions

- add a detector test with a minimal fixture
- improve report wording for non-security reviewers
- improve docs or demo workflows
- add a narrowly scoped framework, provider, or model pattern
- improve SARIF rule help text

## Detector Changes

Detector changes should include tests that cover:

- a positive finding
- a nearby non-match when practical
- source path and confidence expectations
- no secret value leakage when relevant

Prefer simple pattern matching or standard-library parsing. If a detector needs
deeper parsing, keep the behavior explainable and deterministic.

## Report and Schema Changes

If JSON output changes, update:

- `docs/output-schema.json`
- report tests
- README or report guide if the behavior is user-visible

Markdown, HTML, Mermaid, SARIF, and CycloneDX output should remain readable
without network access.
