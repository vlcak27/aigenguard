# Agent Risk Taxonomy

AigenGuard's roadmap focuses on review categories that commonly matter before
AI-agent changes land in git. The taxonomy is intentionally narrow and tied to
deterministic static evidence.

## Risky Agent Capabilities

Capabilities are code, config, or prompt signals that suggest an agent may be
able to perform sensitive actions.

Current and future focus areas include:

- shell or process execution
- code execution
- filesystem access
- network or browser access
- database access
- cloud or administrative access

Capability findings mean the repository appears capable of the action. They do
not prove the action executed.

## MCP Exposure

MCP exposure covers visible Model Context Protocol configuration and the risk
categories suggested by server commands, args, packages, transports, and env
variable names.

AigenGuard focuses on whether MCP servers appear expected, risky, reachable
from nearby agent context, and documented by policy. It does not execute MCP
servers or verify package authenticity.

## Policy Gaps

Policy gaps are places where risky agent behavior appears without matching
documentation or configured policy.

Examples include sensitive capabilities without a reviewed `aigenguard.toml`,
prompt-authorized shell access without controls, or MCP servers that are not
allowed or denied explicitly.

## Credential Context

Credential context includes AI provider names, model identifiers, secret
reference names, and likely AI/API credential leaks.

AigenGuard records names and redacted metadata only. It must not store or print
secret values.

## Runtime Evidence

Runtime evidence is optional supporting context from RunBOM. It can help teams
compare static expectations with observed Python runtime activity during a
chosen command.

RunBOM is not the primary product, not a sandbox, and not policy enforcement.
