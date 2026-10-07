# Security Policy

AigenGuard is a static scanner for reviewing AI agent repositories. It is designed
to run safely against untrusted source trees without executing project code.

AgentBOM has been renamed to AigenGuard. The `agentbom` CLI remains a
compatibility alias, and `agentbom.toml` remains a compatibility fallback. New
projects should use `aigenguard` and `aigenguard.toml`.

## Supported Versions

Security fixes are prioritized for the current release line.

| Version | Supported |
| --- | --- |
| latest minor release | Supported |
| previous minor release | Best effort |
| older versions | Unsupported or best effort only |

## Reporting a Vulnerability

Please report security issues through GitHub private vulnerability reporting if
it is enabled for the repository. If it is not available, open a minimal public
issue that does not include exploit details or private data, and ask for a
private contact path.

Do not include secret values, private repository contents, customer data, or
payloads that execute code.

Useful reports include:

- AigenGuard version
- operating system and Python version
- exact command used
- minimal non-sensitive reproduction files
- expected behavior
- observed behavior

## Security Boundaries

The `scan`, `review` and local guard operations are static only:

- AigenGuard does not execute scanned code.
- AigenGuard does not import scanned modules.
- AigenGuard does not execute MCP servers.
- AigenGuard does not contact networks during scanning.
- AigenGuard avoids following symlink loops.
- AigenGuard skips binary-looking and oversized files.
- AigenGuard records secret reference names.
- AigenGuard may detect likely AI/API credential values.
- Secret values must never be printed, stored, serialized, or included in reports.
- Secret leak findings use redacted metadata only.

Findings are review signals and should not be treated as proof of exploitability
without human review.

RunBOM is separate and intentionally executes a configured/autodetected command;
it is experimental instrumentation, not a sandbox or runtime enforcement.

In 0.9.0, Action inputs pass through environment variables and quoted arguments;
unknown enum/boolean values are rejected. Earlier direct shell interpolation
could execute commands **if an untrusted party could influence an Action input**.
Static policy sections now reject unknown keys rather than silently ignoring
misspelled restrictions. Error messages identify the known section without
printing unknown names or values. `[runbom]` remains a separate runtime table.

PR review trusts the selected base policy, not a candidate's relaxed policy.
Protect the workflow and select the target branch base SHA. Install an approved
scanner wheel before checkout; never install the scanner or dependencies from
PR data. Configured permissions are not evidence of runtime access or an exploit.
