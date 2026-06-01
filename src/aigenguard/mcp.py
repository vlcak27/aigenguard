"""MCP configuration parsing and risk classification."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
import re


MCP_CONFIG_FILENAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
RISK_CATEGORY_ORDER = (
    "filesystem_access",
    "shell_process_execution",
    "browser_network_access",
    "database_access",
    "cloud_access",
    "secrets_env_access",
    "unknown_custom_server",
)
HIGH_RISK_CATEGORIES = {
    "filesystem_access",
    "shell_process_execution",
    "secrets_env_access",
}
MEDIUM_RISK_CATEGORIES = {
    "browser_network_access",
    "database_access",
    "cloud_access",
}
RISK_PATTERNS = {
    "filesystem_access": (
        "filesystem",
        "file-system",
        "file_system",
        "fs",
        "read_file",
        "write_file",
        "directory",
        "path",
        "desktop-commander",
    ),
    "shell_process_execution": (
        "shell",
        "terminal",
        "exec",
        "subprocess",
        "run_command",
        "bash",
        "powershell",
        "cmd.exe",
        "desktop-commander",
    ),
    "browser_network_access": (
        "browser",
        "playwright",
        "puppeteer",
        "network",
        "http",
        "https",
        "fetch",
        "web",
        "search",
        "brave-search",
        "url",
        "curl",
    ),
    "database_access": (
        "postgres",
        "postgresql",
        "mysql",
        "sqlite",
        "database",
        "db",
        "redis",
        "mongodb",
        "mongo",
        "supabase",
    ),
    "cloud_access": (
        "aws",
        "boto3",
        "gcp",
        "google-cloud",
        "azure",
        "cloud",
        "cloudflare",
        "vercel",
        "s3",
    ),
    "secrets_env_access": (
        "secret",
        "secrets",
        "token",
        "api_key",
        "apikey",
        "credential",
        "password",
        "private_key",
        "vault",
    ),
}
SHELL_COMMAND_NAMES = {"bash", "cmd", "cmd.exe", "powershell", "pwsh", "sh", "zsh"}


def is_mcp_config_path(relpath: str) -> bool:
    path = PurePosixPath(relpath)
    filename = path.name.lower()
    if filename in MCP_CONFIG_FILENAMES:
        return True
    parts = {part.lower() for part in path.parts}
    return filename == "mcp.json" and bool(parts & {".cursor", "cursor", "claude"})


def analyze_mcp_config(
    relpath: str,
    text: str | None,
    confidence: str,
) -> list[dict[str, object]]:
    """Parse a JSON MCP config and return deterministic server findings."""
    if not is_mcp_config_path(relpath):
        return []
    if text is None:
        return [_config_finding(relpath, confidence, "unreadable")]

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [_config_finding(relpath, confidence, "invalid_json")]

    servers = _extract_server_definitions(data)
    if not servers:
        return [_config_finding(relpath, confidence, "no_servers")]

    findings = []
    for name, definition in servers:
        findings.append(_server_finding(name, definition, relpath, confidence))
    return findings


def _config_finding(relpath: str, confidence: str, status: str) -> dict[str, object]:
    finding: dict[str, object] = {
        "name": PurePosixPath(relpath).name,
        "path": relpath,
        "confidence": confidence,
        "kind": "config_file",
        "parse_status": status,
    }
    if status == "invalid_json":
        finding["risk"] = "low"
        finding["risk_categories"] = ["unknown_custom_server"]
        finding["rationale"] = ["MCP config could not be parsed as JSON"]
    return finding


def _extract_server_definitions(data: object) -> list[tuple[str, object]]:
    candidates: list[object] = []
    if isinstance(data, dict):
        for key in ("mcpServers", "mcp_servers", "servers"):
            candidates.append(data.get(key))
        for key in ("mcp", "modelContextProtocol", "model_context_protocol"):
            nested = data.get(key)
            if isinstance(nested, dict):
                for server_key in ("mcpServers", "mcp_servers", "servers"):
                    candidates.append(nested.get(server_key))

    servers: list[tuple[str, object]] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            for name, definition in sorted(candidate.items(), key=lambda item: str(item[0])):
                servers.append((str(name), definition))
        elif isinstance(candidate, list):
            for index, definition in enumerate(candidate):
                if isinstance(definition, dict):
                    name = str(definition.get("name") or definition.get("id") or f"server-{index + 1}")
                else:
                    name = f"server-{index + 1}"
                servers.append((name, definition))
    return servers


def _server_finding(
    name: str,
    definition: object,
    relpath: str,
    confidence: str,
) -> dict[str, object]:
    command = _string_value(definition, "command")
    args = _string_list_value(definition, "args")
    env_names = _env_names(definition)
    transport = _transport(definition)
    package = _package_or_binary(command, args)
    categories = _risk_categories(name, command, args, env_names, transport, package, definition)
    risk = _risk_for_categories(categories)
    rationale = _risk_rationale(categories, name, command, package, env_names)

    finding: dict[str, object] = {
        "name": name,
        "path": relpath,
        "confidence": confidence,
        "kind": "server",
        "parse_status": "parsed",
        "risk": risk,
        "risk_categories": categories,
        "rationale": rationale,
    }
    if command:
        finding["command"] = command
    if args:
        finding["args"] = args
    if env_names:
        finding["env"] = env_names
    if transport:
        finding["transport"] = transport
    if package:
        finding["package"] = package
    return finding


def _string_value(definition: object, key: str) -> str:
    if isinstance(definition, dict) and isinstance(definition.get(key), str):
        return str(definition[key])
    if key == "command" and isinstance(definition, str):
        return definition
    return ""


def _string_list_value(definition: object, key: str) -> list[str]:
    if not isinstance(definition, dict):
        return []
    value = definition.get(key)
    if not isinstance(value, list):
        return []
    return _safe_args([str(item) for item in value if isinstance(item, (str, int, float, bool))])


def _safe_args(args: list[str]) -> list[str]:
    safe = []
    redact_next = False
    for arg in args:
        if redact_next:
            safe.append("[redacted]")
            redact_next = False
            continue
        lowered = arg.lower()
        if _looks_secret_flag(lowered):
            if "=" in arg:
                name, _value = arg.split("=", 1)
                safe.append(f"{name}=[redacted]")
            else:
                safe.append(arg)
                redact_next = True
            continue
        safe.append(_redact_url_value(arg))
    return safe


def _looks_secret_flag(value: str) -> bool:
    return any(
        token in value
        for token in ("api-key", "api_key", "token", "secret", "password", "credential", "private-key")
    )


def _env_names(definition: object) -> list[str]:
    if not isinstance(definition, dict):
        return []
    env = definition.get("env")
    names: set[str] = set()
    if isinstance(env, dict):
        names.update(str(key) for key in env)
    elif isinstance(env, list):
        for item in env:
            if isinstance(item, str):
                names.add(item.split("=", 1)[0].strip())
            elif isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str):
                    names.add(name)
    return sorted(name for name in names if name)


def _transport(definition: object) -> str:
    if not isinstance(definition, dict):
        return ""
    for key in ("transport", "type"):
        value = definition.get(key)
        if isinstance(value, str):
            return value
    if any(isinstance(definition.get(key), str) for key in ("url", "endpoint")):
        return "http"
    if definition.get("command"):
        return "stdio"
    return ""


def _package_or_binary(command: str, args: list[str]) -> str:
    command_name = PurePosixPath(command).name if command else ""
    if command_name in {"npx", "pnpm", "yarn", "bunx", "uvx"}:
        package = _first_non_option(args)
        return package or command_name
    if command_name in {"python", "python3", "py"} and "-m" in args:
        index = args.index("-m")
        if index + 1 < len(args):
            return args[index + 1]
    if command_name == "node" and args:
        return PurePosixPath(args[0]).name
    return command_name or _first_non_option(args)


def _first_non_option(args: list[str]) -> str:
    for arg in args:
        if arg != "[redacted]" and not arg.startswith("-"):
            return arg
    return ""


def _risk_categories(
    name: str,
    command: str,
    args: list[str],
    env_names: list[str],
    transport: str,
    package: str,
    definition: object,
) -> list[str]:
    haystack = " ".join(
        [
            name,
            command,
            package,
            transport,
            " ".join(args),
            " ".join(env_names),
            _safe_definition_context(definition),
        ]
    ).lower()
    categories = []
    for category in RISK_CATEGORY_ORDER:
        if category == "unknown_custom_server":
            continue
        if category == "secrets_env_access" and env_names:
            categories.append(category)
            continue
        if _category_matches(category, haystack, command, args):
            categories.append(category)
    if not categories:
        categories.append("unknown_custom_server")
    return categories


def _category_matches(
    category: str,
    haystack: str,
    command: str,
    args: list[str],
) -> bool:
    if category == "shell_process_execution" and _has_shell_command(command, args):
        return True
    return any(pattern in haystack for pattern in RISK_PATTERNS[category])


def _has_shell_command(command: str, args: list[str]) -> bool:
    command_name = PurePosixPath(command).name.lower()
    if command_name in SHELL_COMMAND_NAMES:
        return True
    return any(arg.lower() in SHELL_COMMAND_NAMES for arg in args)


def _safe_definition_context(definition: object) -> str:
    if not isinstance(definition, dict):
        return ""
    values = []
    for key in ("url", "endpoint"):
        value = definition.get(key)
        if isinstance(value, str):
            values.append(_redact_url_value(value))
    return " ".join(values)


def _redact_url_value(value: str) -> str:
    return re.sub(r"://[^/@]+@", "://", value)


def _risk_for_categories(categories: list[str]) -> str:
    if any(category in HIGH_RISK_CATEGORIES for category in categories):
        return "high"
    if any(category in MEDIUM_RISK_CATEGORIES for category in categories):
        return "medium"
    return "low"


def _risk_rationale(
    categories: list[str],
    name: str,
    command: str,
    package: str,
    env_names: list[str],
) -> list[str]:
    rationale = []
    if "filesystem_access" in categories:
        rationale.append("server name or package suggests filesystem access")
    if "shell_process_execution" in categories:
        rationale.append("server name or command suggests shell or process execution")
    if "browser_network_access" in categories:
        rationale.append("server name or config suggests browser or network access")
    if "database_access" in categories:
        rationale.append("server name or package suggests database access")
    if "cloud_access" in categories:
        rationale.append("server name or package suggests cloud access")
    if "secrets_env_access" in categories:
        rationale.append(f"server declares environment variables: {', '.join(env_names)}")
    if "unknown_custom_server" in categories:
        package_detail = package or command or name
        rationale.append(f"custom or unknown MCP server: {package_detail}")
    return rationale
