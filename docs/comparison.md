# Comparison

AigenGuard is scoped as a local-first pre-commit policy guard for AI-agent
repositories. It is meant to complement adjacent security tools, not replace
them.

## AigenGuard vs SAST

SAST tools focus on language-specific vulnerability patterns such as injection,
unsafe deserialization, taint flow, and framework misuse.

AigenGuard focuses on agent-repository review signals: prompts, agent
frameworks, MCP configuration, risky capabilities, policy gaps, and AI/API
credential context. It does not try to provide broad language vulnerability
coverage.

## AigenGuard vs Secret Scanners

Secret scanners are built for broad credential discovery across many providers,
formats, histories, and validation models.

AigenGuard detects likely AI/API credential leaks and credential context when
those signals affect agent repository review. Values are redacted. It is not a
replacement for dedicated secret scanners such as Gitleaks or TruffleHog.

## AigenGuard vs MCP Scanners

MCP scanners may focus on inventorying MCP servers, packages, or deployed MCP
surfaces.

AigenGuard treats MCP configuration as one part of an AI-agent repository
policy review. It parses supported config as data, classifies visible risk
categories, and relates MCP exposure to nearby agent and prompt context when
static evidence supports it.

## AigenGuard vs Runtime Sandboxes

Runtime sandboxes attempt to contain or observe behavior while code runs.

AigenGuard's pre-commit guard and static scan do not execute scanned code,
import scanned modules, start MCP servers, or contact networks. Optional RunBOM
runtime evidence is best-effort instrumentation, not a sandbox and not policy
enforcement.
