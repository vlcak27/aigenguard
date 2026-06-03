# AigenGuard 0.9 Roadmap

AigenGuard 0.9 is a positioning and credibility release.

## 0.9 Goal

Make AigenGuard easy to understand, evaluate, and trust as a local-first
pre-commit policy guard for AI-agent repositories.

0.9 is not a detector expansion release. The priority is clearer product
identity, simpler docs, honest limits, stable compatibility, and visible
precision work.

AgentBOM is now AigenGuard. The `agentbom` CLI and `agentbom.toml` remain supported during migration. New projects should use `aigenguard` and `aigenguard.toml`.

## Focus Areas

### First Impression

Outcome:

- A new user can understand the product in under a minute.
- The primary workflow is clear: install, activate, commit.
- RunBOM appears as optional evidence, not the main product.
- AgentBOM compatibility remains visible but secondary.

Planned work:

- Keep README and package language centered on local pre-commit policy review.
- Lead with `pip install aigenguard`, `aigenguard activate`, and `git commit`.
- Show one short blocked-change example with Why, Fix, and redaction behavior.
- Keep optional reports and RunBOM below the primary workflow.

Non-goals:

- Marketing-heavy copy.
- Cloud service positioning.
- Making reports or runtime evidence feel required for basic use.

### Product Simplicity

Outcome:

- The command surface feels small and predictable.
- `aigenguard activate` is the default setup path.
- `aigenguard scan` remains useful for manual review and CI.

Planned work:

- Keep activation, status, deactivate, and guard behavior easy to explain.
- Keep policy modes understandable: advisory, confirm, enforce.
- Keep report filenames stable for existing automation.
- Keep examples close to common AI-agent repository layouts.

Non-goals:

- New command families unrelated to pre-commit review.
- Hosted policy setup.
- Broad security platform features.

### Trust Model

Outcome:

- Users understand what static scan does and does not do.
- Static review remains local, offline, deterministic, and designed for
  untrusted source trees.
- RunBOM has a clearly separate trust boundary.

Planned work:

- Keep the threat model documented in `docs/threat-model.md`.
- State that static scan does not execute code, import modules, execute MCP
  servers, or make network calls.
- Keep secret values redacted and out of outputs.
- Explain RunBOM as optional runtime evidence that intentionally executes a
  configured or autodetected command.
- Preserve AgentBOM migration support: CLI alias, import aliases,
  `agentbom.toml` fallback, report filenames, `.agentbom/` artifacts, and hook
  bypass alias.

Non-goals:

- Runtime isolation claims.
- Exploit verification claims.
- Telemetry or remote scanning.
- Secret value collection.

### Technical Discipline

Outcome:

- Changes are small, test-backed, and explainable.
- Findings remain deterministic review signals with source paths, confidence,
  rationale, and guidance where static evidence supports it.

Planned work:

- Keep detection dependency-light.
- Prefer standard-library parsers and simple pattern matching in v0.x.
- Expand regression tests before broadening detector categories.
- Keep generated output stable enough for review and CI diffs.
- Keep docs and examples synchronized with actual behavior.

Non-goals:

- Runtime policy enforcement.
- LLM-generated findings.
- Deep language-specific SAST rules.
- New runtime dependencies without a clear maintenance reason.

### Differentiation

Outcome:

- AigenGuard is positioned by its narrow scope: AI-agent repository review before
  commit.
- Adjacent tools are treated as complements, not competitors to replace.

Planned work:

- Keep `docs/comparison.md` concise and factual.
- Keep `docs/agent-risk-taxonomy.md` focused on review categories.
- Use examples that reflect realistic changes a reviewer may want to catch in
  git.

Non-goals:

- Broad package vulnerability scanning.
- Full secret scanner parity.
- Generic MCP inventory unrelated to repository policy.
- SBOM, SPDX, or CycloneDX replacement positioning.

### Precision Corpus

Outcome:

- Precision work is visible without overstating what it proves.
- The corpus helps catch obvious regressions and guides future detector work.

Planned work:

- Keep `benchmarks/precision/README.md` clear about scope and limits.
- Maintain representative good cases for documentation mentions, placeholders,
  and policy-documented capabilities.
- Maintain representative bad cases for risky capabilities, MCP exposure,
  leaked credential values, and policy gaps.
- Report corpus results in CI.

Non-goals:

- Claims of broad vulnerability coverage.
- Metrics that imply exploitability.
- Benchmarks that require network services or executing scanned code.

## Release Criteria

- README opens with the product identity, problem, primary workflow, blocked
  example, and local-first trust model.
- RunBOM is documented as optional supporting evidence.
- AgentBOM compatibility remains documented without dominating first-run docs.
- Threat model, comparison, and agent-risk taxonomy docs are present and
  aligned.
- Examples demonstrate expected and risky AI-agent repository changes.
- Precision corpus runs in CI and documents its limits.
- Required validation passes: Ruff, `git diff --check`, and pytest.

## Non-Goals

- Dashboard.
- Cloud service.
- Runtime isolation feature.
- AI chatbot.
- Detector expansion without precision work.
- Runtime policy enforcement.
- SPDX, CycloneDX, or SBOM replacement behavior.
