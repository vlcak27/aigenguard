"""Plugin-style detectors for AigenGuard v0.1."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import json
import re
from pathlib import PurePosixPath
import tomllib
from typing import Protocol

from .mcp import MCP_CONFIG_FILENAMES, analyze_mcp_config

PROVIDERS = {
    "openai": ("openai", "OPENAI_API_KEY"),
    "anthropic": ("anthropic", "ANTHROPIC_API_KEY"),
    "gemini": (
        "gemini",
        "google.generativeai",
        "google.genai",
        "@google/generative-ai",
        "@google/genai",
        "vertexai.generative_models",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENERATIVE_AI_API_KEY",
    ),
    "ollama": ("ollama", "OLLAMA_HOST", "OLLAMA_BASE_URL", "localhost:11434"),
    "deepseek": ("deepseek", "DEEPSEEK_API_KEY", "api.deepseek.com"),
    "openrouter": ("openrouter", "OPENROUTER_API_KEY", "openrouter.ai/api/v1"),
}

MODEL_PREFIX_RE = (
    r"(?:(?:(?:openrouter|litellm)/)?"
    r"(?:openai|anthropic|google|deepseek|meta-llama|mistral|xai|cohere|perplexity|qwen)/)?"
)
OPENAI_MODEL_RE = (
    r"(?:gpt-(?:(?:\d+(?:\.\d+)?)|4o)(?:-(?:pro|mini|nano|preview|latest))?"
    r"|o(?:1|3)(?:-mini)?|o4-mini)"
)
ANTHROPIC_MODEL_RE = (
    r"(?:claude-(?:(?:opus|sonnet|haiku)-\d+(?:[.-]\d+)?"
    r"|3(?:\.\d+)?(?:-(?:opus|sonnet|haiku)(?:-\d{8})?)?))"
)
GEMINI_MODEL_RE = r"(?:gemini-(?:pro|\d+(?:\.\d+)?-(?:pro|flash(?:-lite)?)))"
DEEPSEEK_MODEL_RE = r"(?:deepseek-(?:chat|reasoner|r1|v3|coder))"
LLAMA_MODEL_RE = (
    r"(?:(?:code-?llama)|(?:llama-?\d+(?:\.\d+)?(?:-\d+b)?(?:-instruct)?))"
)
MISTRAL_MODEL_RE = (
    r"(?:(?:mistral-(?:large(?:-latest)?|small|medium))|codestral|mixtral-8x(?:7|22)b)"
)
QWEN_MODEL_RE = r"(?:qwen\d+(?:\.\d+)?(?:-(?:coder|\d+b(?:-instruct)?))?)"
GROK_MODEL_RE = r"(?:grok(?:-\d+)?)"
COHERE_MODEL_RE = r"(?:command-r(?:-plus)?)"
PERPLEXITY_MODEL_RE = r"(?:sonar(?:-(?:pro|reasoning))?)"
MODEL_CORE_RE = (
    rf"(?:{OPENAI_MODEL_RE}|{ANTHROPIC_MODEL_RE}|{GEMINI_MODEL_RE}|"
    rf"{DEEPSEEK_MODEL_RE}|{LLAMA_MODEL_RE}|{MISTRAL_MODEL_RE}|{QWEN_MODEL_RE}|"
    rf"{GROK_MODEL_RE}|{COHERE_MODEL_RE}|{PERPLEXITY_MODEL_RE})"
)
MODEL_PATTERNS = (
    re.compile(
        rf"(?<![A-Za-z0-9_.-])(?P<model>{MODEL_PREFIX_RE}{MODEL_CORE_RE})"
        r"(?![A-Za-z0-9_.-])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_.-])(?P<model>(?:claude[-\s]+)?"
        r"(?:opus|sonnet|haiku)[-\s]?\d+(?:\.\d+)?)"
        r"(?![A-Za-z0-9_.-])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_.-])(?P<model>(?:google/)?gemini[-\s]+"
        r"(?:pro|\d+(?:\.\d+)?[-\s]+(?:pro|flash(?:[-\s]+lite)?)))"
        r"(?![A-Za-z0-9_.-])",
        re.IGNORECASE,
    ),
)
AMBIGUOUS_STANDALONE_MODELS = {"grok", "sonar"}
MODEL_CONTEXT_RE = re.compile(
    r"\b(?:model|models|llm|chat[_-]?model|model[_-]?name|deployment|router)\b",
    re.IGNORECASE,
)

FRAMEWORKS = {
    "ag2": ("ag2", "autogen_agentchat", "autogen_core", "autogen_ext"),
    "autogen": ("autogen", "pyautogen"),
    "claude_agent_sdk": ("claude-agent-sdk", "@anthropic-ai/claude-agent-sdk"),
    "crewai": ("crewai",),
    "dspy": ("dspy", "dspy-ai"),
    "google_adk": ("google.adk", "google-adk"),
    "haystack": ("haystack", "haystack-ai", "farm-haystack"),
    "instructor": ("instructor",),
    "langchain": ("langchain",),
    "langgraph": ("langgraph", "@langchain/langgraph"),
    "langserve": ("langserve",),
    "litellm": ("litellm",),
    "llamaindex": ("llama_index", "llamaindex"),
    "mastra": ("@mastra/core", "mastra"),
    "openai_agents": (
        "openai-agents",
        "@openai/agents",
        "from agents import Agent",
        "from agents import Runner",
    ),
    "pydantic_ai": ("pydantic_ai", "pydantic-ai"),
    "semantic_kernel": ("semantic_kernel", "semantic-kernel"),
    "vercel_ai_sdk": ("@ai-sdk/", "@vercel/ai", 'from "ai"', "from 'ai'"),
}
DEPENDENCY_CATEGORIES = {
    "ai_framework": {
        "@anthropic-ai/claude-agent-sdk",
        "@mastra/core",
        "@openai/agents",
        "@vercel/ai",
        "ag2",
        "ai",
        "autogen",
        "autogen-agentchat",
        "autogen-core",
        "autogen-ext",
        "claude-agent-sdk",
        "crewai",
        "dspy",
        "dspy-ai",
        "farm-haystack",
        "google-adk",
        "haystack-ai",
        "instructor",
        "langchain",
        "langchain-community",
        "langgraph",
        "langserve",
        "litellm",
        "llama-index",
        "llama_index",
        "openai-agents",
        "pydantic-ai",
        "pydantic_ai",
        "pyautogen",
        "semantic-kernel",
        "semantic_kernel",
    },
    "mcp": {
        "mcp",
        "fastmcp",
        "modelcontextprotocol",
    },
    "provider_sdk": {
        "@ai-sdk/anthropic",
        "@ai-sdk/google",
        "@ai-sdk/openai",
        "@anthropic-ai/sdk",
        "@google/genai",
        "@google/generative-ai",
        "anthropic",
        "async-openai",
        "deepseek",
        "github.com/sashabaranov/go-openai",
        "google-genai",
        "google-generativeai",
        "ollama",
        "openai",
        "openrouter",
    },
    "sandbox_runtime": {
        "docker",
        "e2b",
        "firecracker",
        "modal",
        "nsjail",
        "podman",
        "pyodide",
        "restrictedpython",
        "wasmtime",
    },
}
JS_MANIFEST_NAMES = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
JS_ONLY_DEPENDENCIES = {"ai"}

CAPABILITIES = {
    "shell": ("subprocess", "os.system", "shell=True"),
    "code_execution": ("eval(", "exec("),
    "network": ("requests.", "httpx.", "aiohttp", "urllib.request"),
    "database": ("sqlite3", "psycopg", "sqlalchemy", "pymongo"),
    "cloud": ("boto3", "google.cloud", "azure."),
    "mcp_tool_invocation": ("call_tool", "invoke_tool", "mcp.client", "mcp.client_session"),
}
CAPABILITY_REGEXES = {
    "autonomous_execution": (
        r"\bwhile\s+true\s*:",
        r"\bwhile\s*\(\s*true\s*\)",
        r"\bfor\s*\(\s*;\s*;\s*\)",
        r"\bmax[_-]?iterations\b\s*[:=]\s*(?:[2-9]|\d{2,})",
        r"\bauto[_-]?run\b\s*[:=]\s*true\b",
        r"\bcontinuous[_-]?mode\b\s*[:=]\s*true\b",
    ),
}

MCP_CONFIG_NAMES = MCP_CONFIG_FILENAMES
PROMPT_NAMES = {"AGENTS.md", "CLAUDE.md"}
POLICY_NAMES = {"policy.md", "policies.md", "security.md", "permissions.md"}
PROMPT_SHELL_PERMISSION_PATTERNS = (
    re.compile(
        r"\b(?:shell|bash|terminal|command(?:s)?)\s+execution\s+is\s+allowed\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:shell|bash|terminal)\s+commands\s+are\s+allowed\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byou\s+may\s+(?:use|run|execute)\s+(?:the\s+)?"
        r"(?:shell|bash|terminal|command(?:s)?)\b",
        re.IGNORECASE,
    ),
)
PROMPT_CODE_PERMISSION_PATTERNS = (
    re.compile(
        r"\b(?:eval|exec|dynamic\s+code\s+execution)\s+is\s+allowed\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byou\s+may\s+(?:use|run|execute)\s+(?:eval|exec|dynamic\s+code)\b",
        re.IGNORECASE,
    ),
)
GENERIC_SECRET_NAMES = {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"}
SECRET_NAME_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|secret|password|credential|private[_-]?key)[A-Z0-9_]*)\b\s*[:=]"
)
SECRET_VALUE_PATTERNS = (
    (
        "openai",
        "api_key",
        "Possible OpenAI API key value",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-|svcacct-)?"
            r"[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "anthropic",
        "api_key",
        "Possible Anthropic API key value",
        re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    (
        "google_gemini",
        "api_key",
        "Possible Google/Gemini API key value",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    ),
    (
        "huggingface",
        "token",
        "Possible Hugging Face token value",
        re.compile(r"(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9_-])"),
    ),
    (
        "github",
        "token",
        "Possible GitHub token value",
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,})(?![A-Za-z0-9_-])"
        ),
    ),
)
GENERIC_SECRET_VALUE_RE = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)\b
    \s*(?::|=)\s*
    (?P<quote>["']?)
    (?P<value>[^"'\s#,;]+)
    (?P=quote)?
    """
)
COHERE_SECRET_VALUE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9]{40,}(?![A-Za-z0-9_-])")
PLACEHOLDER_SECRET_VALUES = {
    "api_key",
    "apikey",
    "changeme",
    "dummy",
    "example",
    "fake",
    "placeholder",
    "replace-me",
    "replace_me",
    "test",
    "token",
    "your-api-key",
    "your_api_key",
    "your-token",
}
ENV_REFERENCE_MARKERS = (
    "${",
    "os.environ",
    "os.getenv",
    "process.env",
    "getenv(",
    "env.",
)


@dataclass(frozen=True)
class DetectionContext:
    """File data passed to detectors."""

    relpath: str
    text: str | None = None
    tree: ast.AST | None = None

    @property
    def lower_text(self) -> str:
        return "" if self.text is None else self.text.lower()

    @property
    def is_python(self) -> bool:
        return PurePosixPath(self.relpath).suffix.lower() == ".py"


@dataclass
class DetectionResult:
    """Findings returned by a detector."""

    findings: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    has_policy: bool = False


class Detector(Protocol):
    """Interface implemented by all built-in and external detectors."""

    name: str

    def detect(self, context: DetectionContext) -> DetectionResult:
        """Return findings for one file."""


class PromptDetector:
    name = "prompt"

    def detect(self, context: DetectionContext) -> DetectionResult:
        path = PurePosixPath(context.relpath)
        filename = path.name
        if filename in PROMPT_NAMES:
            return _result("prompts", _prompt_finding(context.relpath))
        if filename.endswith((".prompt.yaml", ".prompt.yml")):
            return _result("prompts", _prompt_finding(context.relpath))
        if len(path.parts) >= 2 and path.parts[-2] == "prompts" and filename.endswith(".md"):
            return _result("prompts", _prompt_finding(context.relpath))
        return DetectionResult()


class McpConfigDetector:
    name = "mcp_config"

    def detect(self, context: DetectionContext) -> DetectionResult:
        findings = analyze_mcp_config(
            context.relpath,
            context.text,
            confidence_for_path(context.relpath),
        )
        return DetectionResult({"mcp_servers": findings}) if findings else DetectionResult()


class PolicyDetector:
    name = "policy"

    def detect(self, context: DetectionContext) -> DetectionResult:
        filename = PurePosixPath(context.relpath).name.lower()
        return DetectionResult(has_policy=filename in POLICY_NAMES)


class DependencyDetector:
    name = "dependency"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()

        filename = PurePosixPath(context.relpath).name
        if filename == "pyproject.toml":
            dependencies = _parse_pyproject_dependencies(context.text)
        elif filename == "requirements.txt":
            dependencies = _parse_requirements_dependencies(context.text)
        elif filename == "package.json":
            dependencies = _parse_package_json_dependencies(context.text)
        elif filename == "package-lock.json":
            dependencies = _parse_package_lock_dependencies(context.text)
        elif filename == "pnpm-lock.yaml":
            dependencies = _parse_pnpm_lock_dependencies(context.text)
        elif filename == "yarn.lock":
            dependencies = _parse_yarn_lock_dependencies(context.text)
        elif filename == "Cargo.toml":
            dependencies = _parse_cargo_dependencies(context.text)
        elif filename == "go.mod":
            dependencies = _parse_go_mod_dependencies(context.text)
        else:
            return DetectionResult()

        findings = []
        for dependency in dependencies:
            category = _dependency_category(dependency, filename)
            if category is None:
                continue
            _append_unique(
                findings,
                {
                    "name": dependency,
                    "category": category,
                    "path": context.relpath,
                    "confidence": dependency_confidence(context.relpath),
                },
            )
        return DetectionResult({"dependencies": findings})


class ModelDetector:
    name = "model"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_model(context.relpath):
            return DetectionResult()

        findings = []
        confidence = confidence_for_path(context.relpath)
        seen_names = set()
        for pattern in MODEL_PATTERNS:
            for match in pattern.finditer(context.text):
                raw_model = match.group("model")
                model = normalize_model_name(raw_model)
                if not _has_model_match_context(context.text, match, model):
                    continue
                if model in seen_names:
                    continue
                seen_names.add(model)
                findings.append(
                    {
                        "type": "model",
                        "name": model,
                        "source_file": context.relpath,
                        "confidence": confidence,
                        "evidence": match.group(0),
                    }
                )
        return DetectionResult({"models": findings})


class ProviderDetector:
    name = "provider"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_provider_or_framework(context.relpath):
            return DetectionResult()
        if context.is_python and context.tree is not None:
            return DetectionResult({"providers": _detect_python_providers(context)})
        return DetectionResult(
            {"providers": _detect_patterns(PROVIDERS, context.lower_text, context.relpath)}
        )


class FrameworkDetector:
    name = "framework"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_provider_or_framework(context.relpath):
            return DetectionResult()
        return DetectionResult(
            {"frameworks": _detect_patterns(FRAMEWORKS, context.lower_text, context.relpath)}
        )


class CapabilityDetector:
    name = "capability"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()
        if context.is_python and context.tree is not None:
            return DetectionResult({"capabilities": _detect_python_capabilities(context)})
        if _is_prompt_path(context.relpath):
            return DetectionResult({"capabilities": _detect_prompt_capabilities(context)})
        if _is_documentation_path(context.relpath):
            return DetectionResult()

        findings = _detect_patterns(CAPABILITIES, context.lower_text, context.relpath)
        for name, patterns in CAPABILITY_REGEXES.items():
            if any(re.search(pattern, context.text, re.IGNORECASE) for pattern in patterns):
                _append_unique(
                    findings,
                    {
                        "name": name,
                        "path": context.relpath,
                        "confidence": capability_confidence(name, context.relpath),
                    },
                )
        return DetectionResult({"capabilities": findings})


class SecretDetector:
    name = "secret"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()

        raw_names = set(SECRET_NAME_RE.findall(context.text))
        raw_names.update(match.group(1) for match in SECRET_ASSIGNMENT_RE.finditer(context.text))
        names = {
            name
            for raw_name in raw_names
            if not _raw_secret_name_looks_like_value(raw_name)
            and (name := normalize_secret_name(raw_name, context.text)) is not None
        }
        confidence = confidence_for_path(context.relpath)
        findings = [
            {"name": name, "path": context.relpath, "confidence": confidence}
            for name in sorted(names)
        ]
        leak_findings = detect_secret_leak_values(context.text, context.relpath)
        result: dict[str, list[dict[str, object]]] = {"secret_references": findings}
        if leak_findings:
            result["secret_leak_findings"] = leak_findings
        return DetectionResult(result)


BUILTIN_DETECTORS: tuple[Detector, ...] = (
    PromptDetector(),
    McpConfigDetector(),
    PolicyDetector(),
    DependencyDetector(),
    ModelDetector(),
    ProviderDetector(),
    FrameworkDetector(),
    CapabilityDetector(),
    SecretDetector(),
)


def detect_in_file(
    relpath: str, text: str | None, detectors: tuple[Detector, ...] = BUILTIN_DETECTORS
) -> DetectionResult:
    """Run detector plugins for one file."""
    combined = DetectionResult()
    context = DetectionContext(relpath=relpath, text=text, tree=_parse_python_ast(relpath, text))
    for detector in detectors:
        result = detector.detect(context)
        combined.has_policy = combined.has_policy or result.has_policy
        for key, items in result.findings.items():
            combined.findings.setdefault(key, [])
            for item in items:
                _append_unique(combined.findings[key], item)
    return combined


def detect_in_text(text: str, relpath: str) -> dict[str, list[dict[str, object]]]:
    """Compatibility wrapper for text-based detections."""
    result = detect_in_file(
        relpath,
        text,
        (
            ModelDetector(),
            ProviderDetector(),
            FrameworkDetector(),
            CapabilityDetector(),
            SecretDetector(),
        ),
    )
    return {
        "models": result.findings.get("models", []),
        "providers": result.findings.get("providers", []),
        "frameworks": result.findings.get("frameworks", []),
        "capabilities": result.findings.get("capabilities", []),
        "secret_references": result.findings.get("secret_references", []),
        "secret_leak_findings": result.findings.get("secret_leak_findings", []),
    }


def detect_mcp_config(relpath: str) -> dict[str, str] | None:
    findings = McpConfigDetector().detect(DetectionContext(relpath)).findings
    return _first(findings.get("mcp_servers", []))


def detect_prompt_file(relpath: str) -> dict[str, str] | None:
    findings = PromptDetector().detect(DetectionContext(relpath)).findings
    return _first(findings.get("prompts", []))


def is_policy_file(relpath: str) -> bool:
    return PolicyDetector().detect(DetectionContext(relpath)).has_policy


def detect_secret_references(text: str, relpath: str) -> list[dict[str, str]]:
    findings = SecretDetector().detect(DetectionContext(relpath, text)).findings
    return [
        item
        for item in findings.get("secret_references", [])
        if isinstance(item, dict)
    ]


def detect_secret_leak_values(text: str, relpath: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _is_comment_only(line):
            continue
        for provider, category, title, pattern in SECRET_VALUE_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if _is_placeholder_secret_value(value):
                    continue
                _append_unique(
                    findings,
                    _secret_leak_finding(
                        provider=provider,
                        category=category,
                        title=title,
                        relpath=relpath,
                        line=line_number,
                        evidence=_redacted_evidence_for_line(line, provider),
                        confidence="high",
                    ),
                )
        for match in GENERIC_SECRET_VALUE_RE.finditer(line):
            name = match.group("name")
            value = match.group("value")
            if _matches_provider_secret_value(value):
                continue
            if _is_env_secret_reference(value) or _is_placeholder_secret_value(value):
                continue
            if not _looks_like_secret_value(value):
                continue
            provider = _provider_for_secret_name(name) or "generic"
            _append_unique(
                findings,
                _secret_leak_finding(
                    provider=provider,
                    category=_generic_secret_category(name),
                    title=f"Possible {_display_secret_name(name)} value",
                    relpath=relpath,
                    line=line_number,
                    evidence=f"{_display_secret_name(name)} = [REDACTED]",
                    confidence="medium" if provider == "generic" else "high",
                ),
            )
        if "cohere" in line.lower() and GENERIC_SECRET_VALUE_RE.search(line) is None:
            for match in COHERE_SECRET_VALUE_RE.finditer(line):
                value = match.group(0)
                if _is_placeholder_secret_value(value):
                    continue
                _append_unique(
                    findings,
                    _secret_leak_finding(
                        provider="cohere",
                        category="api_key",
                        title="Possible Cohere API key value",
                        relpath=relpath,
                        line=line_number,
                        evidence=_redacted_evidence_for_line(line, "cohere"),
                        confidence="medium",
                    ),
                )
    return sort_secret_leak_findings(findings)


def sort_secret_leak_findings(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        items,
        key=lambda item: (
            -_severity_rank(str(item.get("severity", "low"))),
            -_confidence_rank(str(item.get("confidence", "low"))),
            str(item.get("path", "")),
            _line_number(item.get("line")),
            str(item.get("provider", item.get("category", ""))),
        ),
    )


def _secret_leak_finding(
    *,
    provider: str,
    category: str,
    title: str,
    relpath: str,
    line: int,
    evidence: str,
    confidence: str,
) -> dict[str, object]:
    return {
        "provider": provider,
        "category": category,
        "severity": "critical" if provider in {"openai", "anthropic", "github"} else "high",
        "confidence": confidence,
        "path": relpath,
        "line": line,
        "title": title,
        "redacted_evidence": evidence,
        "suggested_action": "Value redacted. Remove the key and rotate it.",
    }


def _redacted_evidence_for_line(line: str, provider: str) -> str:
    assignment = GENERIC_SECRET_VALUE_RE.search(line)
    if assignment is not None:
        return f"{_display_secret_name(assignment.group('name'))} = [REDACTED]"
    return f"{provider} credential value [REDACTED]"


def _display_secret_name(name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return normalized or "SECRET"


def _raw_secret_name_looks_like_value(name: str) -> bool:
    return "_" not in name and len(name) >= 16


def _provider_for_secret_name(name: str) -> str | None:
    normalized = _display_secret_name(name)
    if "OPENAI" in normalized:
        return "openai"
    if "ANTHROPIC" in normalized or "CLAUDE" in normalized:
        return "anthropic"
    if "GEMINI" in normalized or "GOOGLE" in normalized:
        return "google_gemini"
    if "COHERE" in normalized:
        return "cohere"
    if "HUGGINGFACE" in normalized or "HUGGING_FACE" in normalized or normalized.startswith("HF_"):
        return "huggingface"
    if "GITHUB" in normalized:
        return "github"
    return None


def _generic_secret_category(name: str) -> str:
    normalized = _display_secret_name(name)
    if "API_KEY" in normalized or "ACCESS_KEY" in normalized:
        return "api_key"
    if "TOKEN" in normalized:
        return "token"
    if "PRIVATE_KEY" in normalized:
        return "private_key"
    return "secret"


def _is_comment_only(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(("#", "//"))


def _is_env_secret_reference(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ENV_REFERENCE_MARKERS)


def _is_placeholder_secret_value(value: str) -> bool:
    normalized = value.strip().strip("\"'`").strip()
    lowered = normalized.lower()
    if not lowered:
        return True
    if lowered.startswith("<") and lowered.endswith(">"):
        return True
    if lowered.startswith("${") and lowered.endswith("}"):
        return True
    if lowered in PLACEHOLDER_SECRET_VALUES:
        return True
    if lowered in {"sk-...", "sk-ant-...", "ghp_...", "github_pat_...", "hf_..."}:
        return True
    if any(token in lowered for token in PLACEHOLDER_SECRET_VALUES):
        return True
    return False


def _matches_provider_secret_value(value: str) -> bool:
    return any(pattern.search(value) is not None for *_, pattern in SECRET_VALUE_PATTERNS)


def _looks_like_secret_value(value: str) -> bool:
    stripped = value.strip().strip("\"'`")
    if stripped.startswith("-----BEGIN"):
        return True
    if len(stripped) < 16:
        return False
    if len(set(stripped)) < 6:
        return False
    has_letter = any(char.isalpha() for char in stripped)
    has_digit = any(char.isdigit() for char in stripped)
    has_secret_punctuation = any(char in "_-./+=" for char in stripped)
    return has_letter and (has_digit or has_secret_punctuation)


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


def _confidence_rank(confidence: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(confidence, 0)


def _line_number(value: object) -> int:
    return value if isinstance(value, int) else 0


def detect_capabilities(text: str, lower_text: str, relpath: str) -> list[dict[str, str]]:
    del lower_text
    findings = CapabilityDetector().detect(DetectionContext(relpath, text)).findings
    return findings.get("capabilities", [])


def detect_models(text: str, relpath: str) -> list[dict[str, str]]:
    findings = ModelDetector().detect(DetectionContext(relpath, text)).findings
    return findings.get("models", [])


def _has_model_match_context(text: str, match: re.Match[str], model: str) -> bool:
    if model not in AMBIGUOUS_STANDALONE_MODELS:
        return True
    raw = match.group("model").lower()
    if "/" in raw:
        return True
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    return MODEL_CONTEXT_RE.search(line) is not None


def normalize_model_name(raw: str) -> str:
    normalized = raw.strip().strip("\"'`").lower()
    normalized = re.sub(r"[\s_]+", "-", normalized)
    normalized = re.sub(r"-+", "-", normalized).strip("-")

    for router in ("openrouter/", "litellm/"):
        if normalized.startswith(router):
            normalized = normalized.removeprefix(router)
            break

    for provider in (
        "openai/",
        "anthropic/",
        "google/",
        "deepseek/",
        "meta-llama/",
        "mistral/",
        "xai/",
        "cohere/",
        "perplexity/",
        "qwen/",
    ):
        if normalized.startswith(provider):
            normalized = normalized.removeprefix(provider)
            break

    anthropic = re.fullmatch(
        r"(?:claude-)?(?P<family>opus|sonnet|haiku)-?(?P<version>\d+(?:[.-]\d+)?)",
        normalized,
    )
    if anthropic is not None:
        version = anthropic.group("version").replace("-", ".")
        return f"claude-{anthropic.group('family')}-{version}"

    gemini = re.fullmatch(
        r"gemini-(?P<version>\d+(?:\.\d+)?)-(?P<tier>pro|flash(?:-lite)?)",
        normalized,
    )
    if gemini is not None:
        return f"gemini-{gemini.group('version')}-{gemini.group('tier')}"

    return normalized


def normalize_secret_name(name: str, text: str) -> str | None:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if normalized in GENERIC_SECRET_NAMES:
        provider = provider_context(text)
        if provider is None:
            return None
        return f"{provider}_{normalized}"
    return normalized


def provider_context(text: str) -> str | None:
    lower = text.lower()
    providers = {
        name.upper()
        for name, patterns in PROVIDERS.items()
        if any(pattern.lower() in lower for pattern in patterns)
    }
    if len(providers) == 1:
        return next(iter(providers))
    return None


def can_detect_model(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}


def can_detect_provider_or_framework(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".ts", ".js", ".json", ".yaml", ".yml", ".toml"}


def confidence_for_path(relpath: str) -> str:
    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix in {".py", ".ts", ".js"}:
        return "high"
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return "medium"
    return "low"


def dependency_confidence(relpath: str) -> str:
    filename = PurePosixPath(relpath).name
    if filename in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.mod"}:
        return "medium"
    return confidence_for_path(relpath)


def capability_confidence(name: str, relpath: str) -> str:
    confidence = confidence_for_path(relpath)
    if name == "autonomous_execution" and _is_reference_path(relpath):
        return _downgrade_confidence(confidence)
    return confidence


def _prompt_finding(relpath: str) -> dict[str, str]:
    return {"path": relpath, "type": "prompt", "confidence": confidence_for_path(relpath)}


def _is_prompt_path(relpath: str) -> bool:
    path = PurePosixPath(relpath)
    filename = path.name
    if filename in PROMPT_NAMES:
        return True
    if filename.endswith((".prompt.yaml", ".prompt.yml")):
        return True
    return len(path.parts) >= 2 and path.parts[-2] == "prompts" and filename.endswith(".md")


def _is_documentation_path(relpath: str) -> bool:
    path = PurePosixPath(relpath)
    suffix = path.suffix.lower()
    if suffix not in {".md", ".rst", ".txt"}:
        return False
    return not _is_prompt_path(relpath)


def _detect_prompt_capabilities(context: DetectionContext) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if context.text is None:
        return findings
    confidence = confidence_for_path(context.relpath)
    if any(pattern.search(context.text) for pattern in PROMPT_SHELL_PERMISSION_PATTERNS):
        _append_unique(
            findings,
            {"name": "shell", "path": context.relpath, "confidence": confidence},
        )
    if any(pattern.search(context.text) for pattern in PROMPT_CODE_PERMISSION_PATTERNS):
        _append_unique(
            findings,
            {"name": "code_execution", "path": context.relpath, "confidence": confidence},
        )
    return findings


def _result(key: str, item: dict[str, object]) -> DetectionResult:
    return DetectionResult({key: [item]})


def _first(items: list[dict[str, object]]) -> dict[str, object] | None:
    if not items:
        return None
    return items[0]


def _detect_patterns(
    definitions: dict[str, tuple[str, ...]], lower_text: str, relpath: str
) -> list[dict[str, str]]:
    findings = []
    confidence = confidence_for_path(relpath)
    for name, patterns in definitions.items():
        for pattern in patterns:
            if pattern.lower() in lower_text:
                findings.append({"name": name, "path": relpath, "confidence": confidence})
                break
    return findings


def _append_unique(items: list[dict[str, object]], item: dict[str, object]) -> None:
    if item not in items:
        items.append(item)


def _parse_pyproject_dependencies(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    dependencies: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        _extend_dependency_names(dependencies, project.get("dependencies", []))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                _extend_dependency_names(dependencies, values)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        poetry_dependencies = poetry.get("dependencies", {})
        if isinstance(poetry_dependencies, dict):
            for name in poetry_dependencies:
                if name.lower() != "python":
                    _append_name(dependencies, name)
        poetry_groups = poetry.get("group", {})
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if not isinstance(group, dict):
                    continue
                group_dependencies = group.get("dependencies", {})
                if isinstance(group_dependencies, dict):
                    for name in group_dependencies:
                        _append_name(dependencies, name)

    return dependencies


def _parse_requirements_dependencies(text: str) -> list[str]:
    dependencies: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        name = _dependency_name(line)
        if name:
            _append_name(dependencies, name)
    return dependencies


def _parse_package_json_dependencies(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    dependencies: list[str] = []
    for key in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        values = data.get(key, {})
        if not isinstance(values, dict):
            continue
        for name in values:
            _append_name(dependencies, name)
    return dependencies


def _parse_package_lock_dependencies(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    dependencies: list[str] = []
    _extend_package_json_dependency_map(dependencies, data.get("dependencies", {}))
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for package_path, metadata in packages.items():
            if isinstance(package_path, str):
                name = _name_from_node_modules_path(package_path)
                if name:
                    _append_name(dependencies, name)
            if isinstance(metadata, dict):
                _extend_package_json_dependency_map(dependencies, metadata.get("dependencies", {}))
                _extend_package_json_dependency_map(
                    dependencies, metadata.get("optionalDependencies", {})
                )
                _extend_package_json_dependency_map(dependencies, metadata.get("peerDependencies", {}))
    return dependencies


def _parse_pnpm_lock_dependencies(text: str) -> list[str]:
    dependencies: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "version:", "specifier:")):
            continue
        key = stripped.split(":", 1)[0].strip().strip("'\"")
        name = _package_name_from_lock_key(key)
        if name:
            _append_name(dependencies, name)
    return dependencies


def _parse_yarn_lock_dependencies(text: str) -> list[str]:
    dependencies: list[str] = []
    for line in text.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key = line.split(":", 1)[0].strip().strip("'\"")
        for descriptor in key.split(","):
            name = _package_name_from_lock_key(descriptor.strip().strip("'\""))
            if name:
                _append_name(dependencies, name)
    return dependencies


def _parse_cargo_dependencies(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    dependencies: list[str] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        _extend_toml_dependency_table(dependencies, data.get(key, {}))

    workspace = data.get("workspace", {})
    if isinstance(workspace, dict):
        _extend_toml_dependency_table(dependencies, workspace.get("dependencies", {}))

    target = data.get("target", {})
    if isinstance(target, dict):
        for target_config in target.values():
            if isinstance(target_config, dict):
                _extend_toml_dependency_table(dependencies, target_config.get("dependencies", {}))
    return dependencies


def _parse_go_mod_dependencies(text: str) -> list[str]:
    dependencies: list[str] = []
    in_require_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == ")":
            in_require_block = False
            continue
        if line.startswith("require ("):
            in_require_block = True
            continue
        if line.startswith("require "):
            _append_go_module_name(dependencies, line.removeprefix("require ").strip())
            continue
        if in_require_block:
            _append_go_module_name(dependencies, line)
    return dependencies


def _extend_package_json_dependency_map(dependencies: list[str], values: object) -> None:
    if not isinstance(values, dict):
        return
    for name in values:
        _append_name(dependencies, str(name))


def _extend_toml_dependency_table(dependencies: list[str], values: object) -> None:
    if not isinstance(values, dict):
        return
    for name in values:
        _append_name(dependencies, str(name))


def _append_go_module_name(dependencies: list[str], line: str) -> None:
    if not line:
        return
    module = line.split()[0]
    if module:
        _append_name(dependencies, module)


def _name_from_node_modules_path(package_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    rest = package_path.rsplit(marker, 1)[1]
    parts = rest.split("/")
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _package_name_from_lock_key(key: str) -> str | None:
    normalized = key.strip().strip("'\"").removeprefix("/")
    if not normalized or normalized.startswith(("link:", "file:", "patch:")):
        return None
    if normalized.startswith("@"):
        slash_index = normalized.find("/")
        if slash_index == -1:
            return None
        package_end = normalized.find("@", slash_index)
        if package_end == -1:
            package_end = len(normalized)
        return normalized[:package_end]
    if "@" in normalized:
        return normalized.split("@", 1)[0]
    return normalized


def _extend_dependency_names(dependencies: list[str], values: object) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str):
            continue
        name = _dependency_name(value)
        if name:
            _append_name(dependencies, name)


def _dependency_name(value: str) -> str:
    name = re.split(r"\s*(?:\[|==|!=|~=|>=|<=|>|<|;)\s*", value, maxsplit=1)[0].strip()
    return name.lower().replace("_", "-")


def _dependency_category(name: str, manifest_name: str) -> str | None:
    normalized = name.lower().replace("_", "-")
    if normalized in JS_ONLY_DEPENDENCIES and manifest_name not in JS_MANIFEST_NAMES:
        return None
    for category, names in DEPENDENCY_CATEGORIES.items():
        normalized_names = {item.replace("_", "-") for item in names}
        if normalized in normalized_names:
            return category
    return None


def _is_reference_path(relpath: str) -> bool:
    parts = tuple(part.lower() for part in PurePosixPath(relpath).parts)
    return bool({"test", "tests", "example", "examples", "doc", "docs"} & set(parts))


def _downgrade_confidence(confidence: str) -> str:
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return "low"


def _append_name(items: list[str], item: str) -> None:
    normalized = item.lower().replace("_", "-")
    if normalized and normalized not in items:
        items.append(normalized)


def _parse_python_ast(relpath: str, text: str | None) -> ast.AST | None:
    if text is None or PurePosixPath(relpath).suffix.lower() != ".py":
        return None
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _detect_python_providers(context: DetectionContext) -> list[dict[str, str]]:
    imports = _python_imports(context.tree)
    findings = []
    for provider, modules in {
        "openai": ("openai",),
        "anthropic": ("anthropic",),
        "gemini": ("google.generativeai", "google.genai", "vertexai.generative_models"),
        "ollama": ("ollama",),
        "deepseek": ("deepseek",),
        "openrouter": ("openrouter",),
    }.items():
        if any(_module_matches(imported, modules) for imported in imports) or _text_has_pattern(
            context.lower_text, PROVIDERS[provider]
        ):
            findings.append(
                {
                    "name": provider,
                    "path": context.relpath,
                    "confidence": confidence_for_path(context.relpath),
                }
            )
    return findings


def _detect_python_capabilities(context: DetectionContext) -> list[dict[str, str]]:
    imports = _python_imports(context.tree)
    calls = _python_calls(context.tree)
    findings: list[dict[str, str]] = []
    confidence = confidence_for_path(context.relpath)

    if any(imported == "subprocess" or imported.startswith("subprocess.") for imported in imports):
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if any(
        call
        in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        for call in calls
    ):
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if "os.system" in calls:
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if any(call in {"eval", "exec", "builtins.eval", "builtins.exec"} for call in calls):
        _append_unique(
            findings,
            {"name": "code_execution", "path": context.relpath, "confidence": confidence},
        )
    if _has_python_network_access(imports, calls):
        _append_unique(findings, {"name": "network", "path": context.relpath, "confidence": confidence})
    if _has_python_mcp_tool_invocation(imports, calls):
        _append_unique(
            findings,
            {"name": "mcp_tool_invocation", "path": context.relpath, "confidence": confidence},
        )
    if any(_module_matches(imported, ("boto3", "google.cloud", "azure")) for imported in imports):
        _append_unique(findings, {"name": "cloud", "path": context.relpath, "confidence": confidence})
    if any(_module_matches(imported, ("sqlite3", "psycopg", "sqlalchemy", "pymongo")) for imported in imports):
        _append_unique(
            findings,
            {"name": "database", "path": context.relpath, "confidence": confidence},
        )

    for name, patterns in CAPABILITY_REGEXES.items():
        if context.text is not None and any(
            re.search(pattern, context.text, re.IGNORECASE) for pattern in patterns
        ):
            _append_unique(
                findings,
                {
                    "name": name,
                    "path": context.relpath,
                    "confidence": capability_confidence(name, context.relpath),
                },
            )
    return findings


def _python_imports(tree: ast.AST | None) -> set[str]:
    imports: set[str] = set()
    if tree is None:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            for alias in node.names:
                imports.add(f"{node.module}.{alias.name}")
    return imports


def _python_calls(tree: ast.AST | None) -> set[str]:
    calls: set[str] = set()
    if tree is None:
        return calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name is not None:
                calls.add(name)
    return calls


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent is None:
            return node.attr
        return f"{parent}.{node.attr}"
    return None


def _module_matches(imported: str, modules: tuple[str, ...]) -> bool:
    return any(imported == module or imported.startswith(f"{module}.") for module in modules)


def _text_has_pattern(lower_text: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern.lower() in lower_text for pattern in patterns)


def _has_python_network_access(imports: set[str], calls: set[str]) -> bool:
    if any(_module_matches(imported, ("requests", "httpx", "aiohttp", "urllib.request")) for imported in imports):
        return True
    return any(
        call.startswith(("requests.", "httpx.", "aiohttp.", "urllib.request."))
        for call in calls
    )


def _has_python_mcp_tool_invocation(imports: set[str], calls: set[str]) -> bool:
    has_mcp_import = any(_module_matches(imported, ("mcp",)) for imported in imports)
    if has_mcp_import and any(call.endswith((".call_tool", ".invoke_tool")) for call in calls):
        return True
    return any("mcp" in call.lower() and call.endswith((".call_tool", ".invoke_tool")) for call in calls)
