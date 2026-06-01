# AGENTS.md

## Project

AigenGuard is a minimal open-source CLI that generates a bill of materials for AI agents.

AgentBOM has been renamed to AigenGuard. Keep the `agentbom` CLI compatibility
alias and `agentbom.toml` compatibility fallback. New projects should use
`aigenguard` and `aigenguard.toml`.

## Rules for coding agents

- Keep code simple.
- Do not add runtime dependencies unless asked.
- Do not execute scanned code.
- Do not import scanned code.
- Do not read files larger than 1 MB.
- Do not scan binary files.
- Do not follow symlink loops.
- Never store secret values.
- Never print secret values.
- Never commit .env files.
- The scanner must work offline.
- In v0.1, use simple pattern matching.
- Do not implement CycloneDX or SPDX yet.

## Commands

Install:

pip install -e ".[dev]"

Test:

pytest

Run:

aigenguard scan examples/simple_agent --pretty
