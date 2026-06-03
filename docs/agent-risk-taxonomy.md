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

Policy context is review evidence, not runtime proof. A policy can document why
a high-confidence agent capability is expected without proving the capability is
safe, sandboxed, or unreachable.

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

## Confidence and Review

AigenGuard confidence levels describe static evidence strength. They do not
describe exploitability.

High confidence usually comes from parsed executable code evidence, exact
tool/API call evidence, provider-shaped credential values, or structured config
with a direct risky capability. Medium confidence covers structured config
evidence, MCP metadata, generic secret-like assignments, or risk that needs
reviewer confirmation. Low confidence covers text-only evidence, prompt wording,
inferred cross-file relationships, and weak static signals.

This keeps the taxonomy specific to agent capability, policy context, reviewer
signal, and pre-commit review. It also prepares future capability-diff work
without implementing capability diff in this release.
