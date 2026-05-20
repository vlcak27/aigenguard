# Security Policy

AgentBOM is a static scanner for reviewing AI agent repositories. It is designed
to run safely against untrusted source trees without executing project code.

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

- AgentBOM version
- operating system and Python version
- exact command used
- minimal non-sensitive reproduction files
- expected behavior
- observed behavior

## Security Boundaries

For the 0.8 series, AgentBOM is static analysis only:

- AgentBOM does not execute scanned code.
- AgentBOM does not import scanned modules.
- AgentBOM does not execute MCP servers.
- AgentBOM does not contact networks during scanning.
- AgentBOM avoids following symlink loops.
- AgentBOM skips binary-looking and oversized files.
- AgentBOM records secret reference names.
- AgentBOM may detect likely AI/API credential values.
- Secret values must never be printed, stored, serialized, or included in reports.
- Secret leak findings use redacted metadata only.

Findings are review signals and should not be treated as proof of exploitability
without human review.
