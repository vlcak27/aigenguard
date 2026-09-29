"""Small, data-only model of configured security changes (not runtime access)."""

from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
import re
from urllib.parse import urlsplit


FILESYSTEM_PACKAGE = "@modelcontextprotocol/server-filesystem"
REDACTED = "[redacted]"
SECRET = re.compile(r"(?:sk-(?:proj-|ant-)?|gh[pousr]_|github_pat_|AIza|hf_)[A-Za-z0-9_-]{16,}")


def safe_text(value: str) -> str:
    """Escape terminal controls and redact recognizable tokens in identifiers/paths."""
    value = SECRET.sub(REDACTED, value)
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value)


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def pointer_part(value: str) -> str:
    return safe_text(value).replace("~", "~0").replace("/", "~1")


def change(rule: str, component: str, file: str, field: str, kind: str,
           before: object, after: object, explanation: str, recommendation: str,
           severity: str = "medium", impact: str = "medium") -> dict:
    return {
        "id": rule + "." + fingerprint([component, field, kind, before, after])[:16],
        "rule_id": rule, "component": safe_text(component), "file": safe_text(file),
        "field": safe_text(field), "change": kind, "before": before, "after": after,
        "explanation": explanation, "severity": severity, "recommendation": recommendation,
        "change_confidence": "high", "impact_confidence": impact,
    }


def configured_path(value: str) -> str | None:
    # No expanduser/expandvars, filesystem access, or host-platform path resolution.
    if (not value or value.startswith("//") or "://" in value
            or re.search(r"(?:token|password|secret|api[_-]?key)=", value, re.I)
            or any(char in value for char in "$%~\0\r\n?*")
            or safe_text(value) != value):
        return None
    if re.match(r"^[A-Za-z]:", value) or "\\" in value:
        drive, tail = ntpath.splitdrive(value)
        if not drive and value.startswith("\\"):
            return None
        if drive and not tail.startswith(("/", "\\")):
            return None  # Windows drive-relative paths need process state.
        normalized = ntpath.normpath(value).replace("\\", "/")
        if drive:
            normalized = drive.upper().replace("\\", "/") + normalized[len(drive):]
        family = "windows" if drive else "windows-relative"
    else:
        normalized = posixpath.normpath(value)
        family = "posix" if value.startswith("/") else "relative"
    if ".." in normalized.split("/"):
        return None
    return f"{family}:{normalized}"


def path_scope_change(before: list[str], after: list[str]) -> str:
    if not before or not after:
        return "review_required"  # Empty arguments may defer to runtime MCP Roots.

    def covered(paths, roots):
        return all(any(parts[:len(root)] == root for root in roots) for parts in paths)

    def components(path):
        family, value = path.split(":", 1)
        return (family, *[part for part in value.split("/") if part not in {"", "."}])

    old, new = [components(path) for path in before], [components(path) for path in after]
    # Absolute/relative paths and different drives are not interchangeable.
    old_in_new, new_in_old = covered(old, new), covered(new, old)
    if old_in_new and new_in_old:
        return "no_effect"
    if old_in_new:
        return "expanded"
    if new_in_old:
        return "narrowed"
    return "review_required"


def endpoint_label(value: str) -> str:
    try:
        url = urlsplit(value)
        if url.scheme not in {"https", "http", "ws", "wss"} or not url.hostname:
            return REDACTED
        host = safe_text(url.hostname)
        port = f":{url.port}" if url.port else ""
        return f"{url.scheme}://{host}{port}/[path/query omitted]"
    except ValueError:
        return REDACTED


def mcp_security_config(definition: object) -> dict:
    """Store only selected safe values and digests, never opaque arguments/env values."""
    if isinstance(definition, str):
        definition = {"command": definition}
    if not isinstance(definition, dict):
        return {"schema_version": "1", "complete": False}
    command = definition.get("command", "")
    args = definition.get("args", [])
    env = definition.get("env", {})
    endpoint = definition.get("url", definition.get("endpoint", ""))
    valid = (isinstance(command, str) and isinstance(args, list)
             and all(isinstance(arg, str) for arg in args) and isinstance(endpoint, str)
             and isinstance(env, (dict, list)))
    if not valid:
        return {"schema_version": "1", "complete": False}
    if isinstance(env, list) and any(not isinstance(item, (str, dict)) for item in env):
        return {"schema_version": "1", "complete": False}
    if isinstance(env, dict):
        names = list(env)
    else:
        names = [item.split("=", 1)[0] if isinstance(item, str) else item.get("name", "")
                 for item in env if isinstance(item, (str, dict))]
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
        return {"schema_version": "1", "complete": False}
    names = sorted(set(names))
    known_commands = {"npx", "npx.cmd", "mcp-server-filesystem", "node", "python", "python3", "uvx"}
    package, version, paths, launch_options = "", "", None, []
    arguments = args.copy()
    if command in {"npx", "npx.cmd"}:
        if arguments[:1] in [["-y"], ["--yes"]]:
            launch_options = ["--yes"]
            arguments = arguments[1:]
        if arguments:
            match = re.fullmatch(r"((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)(?:@([^\s]+))?", arguments[0])
            if match:
                package, version = match[1], match[2] or "latest"
                arguments = arguments[1:]
    if command == "mcp-server-filesystem" or (
        command in {"npx", "npx.cmd"} and package == FILESYSTEM_PACKAGE
    ):
        parsed = [configured_path(arg) for arg in arguments if not arg.startswith("-")]
        if len(parsed) == len(arguments) and all(path is not None for path in parsed):
            paths = sorted(set(parsed))
    known = {"command", "args", "env", "url", "endpoint", "transport", "type", "name", "id"}
    return {
        "schema_version": "1", "complete": bool(command or endpoint),
        "command": command if command in known_commands else ("[custom executable]" if command else ""),
        "command_digest": fingerprint(command),
        "package": package if package == FILESYSTEM_PACKAGE else ("[npm package]" if package else ""),
        "package_digest": fingerprint(package),
        "version": version if (version in {"", "latest", "next", "alpha", "beta", "canary"}
                               or re.fullmatch(r"[0-9.*^~<>=|+ -]+", version)) else REDACTED,
        "version_digest": fingerprint(version),
        "fixed_version": bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?", version)),
        "filesystem_paths": paths,
        "args_digest": fingerprint(paths if paths is not None else args),
        "launcher_digest": fingerprint(launch_options),
        "endpoint": endpoint_label(endpoint) if endpoint else "",
        "endpoint_field": "url" if "url" in definition else "endpoint",
        "endpoint_digest": fingerprint({key: definition[key] for key in ("url", "endpoint") if key in definition}),
        "env_names": names,
        "other_digest": fingerprint({key: value for key, value in definition.items() if key not in known}),
        "transport_digest": fingerprint(definition.get("transport", definition.get("type", ""))),
    }


def compare_mcp_servers(before: list[dict], after: list[dict]) -> list[dict]:
    def indexed(items):
        return {(item.get("path", ""), item.get("config_identity", item.get("config_pointer", "/mcpServers/" +
                    pointer_part(str(item.get("name", "")))))): item
                for item in items if isinstance(item, dict) and item.get("kind") == "server"}

    def summary(item):
        metadata = item.get("security_config") or mcp_security_config(item)
        return {key: metadata.get(key) for key in
                ("command", "package", "version", "filesystem_paths", "endpoint", "env_names")}

    old, new = indexed(before), indexed(after)
    changes = []
    for identity in sorted(old.keys() | new.keys()):
        file, pointer = identity
        component = f"{file}#{pointer}"
        left, right = old.get(identity), new.get(identity)
        field_pointer = (right or left).get("config_pointer", pointer)
        if left is None or right is None:
            item = right if left is None else left
            kind = "added" if left is None else "removed"
            changes.append(change("mcp.server", component, file, field_pointer, kind,
                summary(left) if left else None, summary(right) if right else None,
                f"MCP server {kind}; configuration alone does not prove runtime reachability.",
                "Review the server implementation, intended users, and minimum required access.",
                str(item.get("risk", "medium")) if right else "low"))
            continue
        a = left.get("security_config") or mcp_security_config(left)
        b = right.get("security_config") or mcp_security_config(right)
        if not a.get("complete") or not b.get("complete"):
            changes.append(change("mcp.incomplete", component, file, pointer, "incomplete",
                "unavailable", "unavailable", "MCP definition cannot be fully evaluated.",
                "Use a supported JSON server definition and rerun review.", impact="unknown"))
            continue

        def emit(rule, field, kind, prior, current, why, fix, severity="medium", impact="medium"):
            changes.append(change(rule, component, file, field_pointer + ("/" + field if field else ""), kind,
                                  prior, current, why, fix, severity, impact))

        full_metadata = "security_config" in left and "security_config" in right
        if not full_metadata:
            emit("mcp.baseline_coverage", "", "incomplete", "legacy report", "limited metadata",
                 "A legacy report lacks endpoint and opaque configuration metadata.",
                 "Rescan both snapshots with the same current scanner for complete comparison.", impact="unknown")

        if a["command_digest"] != b["command_digest"] or a["package_digest"] != b["package_digest"]:
            field = "command" if a["command_digest"] != b["command_digest"] else "args"
            emit("mcp.execution", field, "review_required",
                 {"command": a["command"], "package": a["package"]},
                 {"command": b["command"], "package": b["package"]},
                 "Configured executable or package changed; its permissions are not inferred.",
                 "Verify the new executable/package origin and required privileges.", impact="unknown")
        if a["package_digest"] == b["package_digest"] and a["version_digest"] != b["version_digest"]:
            floating = a["fixed_version"] and not b["fixed_version"]
            emit("mcp.package_version", "args", "expanded" if floating else "review_required",
                 a["version"], b["version"],
                 "Fixed package version changed to a floating specification." if floating else
                 "Configured package version changed; runtime behavior needs review.",
                 "Review the package release and select an exact reviewed version.",
                 "high" if floating else "medium", "high" if floating else "unknown")
        if a["args_digest"] != b["args_digest"]:
            if (a["filesystem_paths"] is not None and b["filesystem_paths"] is not None
                    and a["command_digest"] == b["command_digest"] and a["package_digest"] == b["package_digest"]):
                kind = path_scope_change(a["filesystem_paths"], b["filesystem_paths"])
                effect = {"expanded": "broadened", "narrowed": "narrowed", "no_effect": "unchanged",
                          "review_required": "changed with uncertain impact"}[kind]
                emit("mcp.filesystem_scope", "args", kind, a["filesystem_paths"], b["filesystem_paths"],
                     f"Configured filesystem directory scope {effect}. Client Roots can override it; "
                     "symlinks and actual runtime access are not evaluated.",
                     "Verify that every configured directory is necessary; prefer project-local roots.",
                     "high" if kind == "expanded" else "medium" if kind == "review_required" else "low",
                     "unknown" if kind == "review_required" else "medium")
            else:
                emit("mcp.arguments", "args", "review_required", REDACTED, REDACTED,
                     "Arguments changed; their access impact is unknown. Values are omitted.",
                     "Review argument order and semantics against this server's documentation.",
                     impact="unknown")
        if full_metadata and a["endpoint_digest"] != b["endpoint_digest"]:
            emit("mcp.endpoint", b["endpoint_field"], "review_required", a["endpoint"], b["endpoint"],
                 "Remote endpoint changed; credentials, path, query, and fragment are omitted.",
                 "Verify the endpoint owner, transport security, and destination of agent data.",
                 impact="unknown")
        if a["env_names"] != b["env_names"]:
            prior, current = set(a["env_names"]), set(b["env_names"])
            kind = "expanded" if current > prior else "narrowed" if prior > current else "review_required"
            emit("mcp.environment", "env", kind, a["env_names"], b["env_names"],
                 "Declared environment variable names changed; values are never recorded.",
                 "Pass only variables the server needs; review any credential-bearing names.",
                 "low" if kind == "narrowed" else "medium")
        if a["launcher_digest"] != b["launcher_digest"]:
            emit("mcp.launch_options", "args", "review_required", REDACTED, REDACTED,
                 "Launcher options changed; directory comparison does not describe launcher behavior.",
                 "Review package-launcher confirmation and execution options.", impact="unknown")
        if full_metadata and (a["other_digest"] != b["other_digest"] or a["transport_digest"] != b["transport_digest"]):
            emit("mcp.other_configuration", "", "review_required", REDACTED, REDACTED,
                 "Other configuration changed; its effect is outside the supported interpretation.",
                 "Review transport/options using the selected client's documentation.", impact="unknown")
    return changes
