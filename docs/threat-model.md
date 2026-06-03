# Threat Model

AigenGuard is a local-first pre-commit policy guard for AI-agent repositories.
Its static scan is designed to be safe to run on untrusted source trees and to
produce deterministic review signals before changes land in git.

## In Scope

- Risky agent capabilities visible in code, prompts, and configuration.
- MCP server exposure visible in supported JSON config files.
- Policy gaps such as sensitive capabilities without documented controls.
- AI provider, model, framework, and AI/API credential context.
- Likely AI/API credential value leaks, with values redacted.

Findings are review signals. They are not exploit proof, runtime validation, or
package authenticity checks.

## Out of Scope

- Runtime sandboxing.
- Hosted scanning or cloud policy management.
- Full language-specific SAST coverage.
- Full secret-scanner parity.
- SBOM, SPDX, or CycloneDX replacement behavior.
- Verification that a deployed agent can actually invoke a specific tool.

## Local-First Assumptions

`aigenguard scan` and the local pre-commit guard:

- do not execute scanned code
- do not import scanned modules
- do not execute MCP servers
- do not make network calls during static scan
- skip files larger than 1 MB
- skip binary-looking files
- avoid symlink loops

The scanner should work offline and produce stable output for the same input
repository and policy.

## Secret Handling

AigenGuard records credential variable names and redacted leak metadata. It must
not store or print secret values in CLI output, JSON, Markdown, HTML, SARIF,
GitHub summaries, tests, or logs.

Secret findings are scoped to AI/API credential context and common secret-like
assignments. Teams should still use a dedicated secret scanner when they need
full secret discovery coverage.

## RunBOM Limitations

RunBOM is optional supporting evidence. Unlike static scan, `aigenguard run`
intentionally executes a configured or autodetected command under best-effort
Python runtime instrumentation.

RunBOM:

- is not part of the pre-commit guard by default
- is not a sandbox
- does not enforce policy yet
- does not prove exploitability
- does not cover all subprocess, native extension, library, or non-Python
  behavior
- writes compatibility artifacts under `.agentbom/`
- must not record secret values
