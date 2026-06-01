"""Experimental RunBOM configuration and runtime command support."""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from .policy_paths import preferred_policy_path


RUNBOM_BASELINE = ".agentbom/runbom-baseline.json"
RUNBOM_LOG = ".agentbom/runbom.jsonl"
RUNBOM_SUMMARY = ".agentbom/runbom-summary.json"
RISK_LEVELS = ("low", "medium", "high", "critical")
RUNTIME_EVENT_TYPES = (
    "filesystem.read",
    "filesystem.write",
    "process.exec",
    "network.connect",
    "env.read",
)
AI_PROVIDER_KEYS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "COHERE_API_KEY",
    "HUGGINGFACE_API_TOKEN",
}
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


@dataclass(frozen=True)
class RunbomDetectedCommand:
    """A command RunBOM can safely prefer without guessing an app entrypoint."""

    command: str
    reason: str


@dataclass(frozen=True)
class RunbomSignalExplanation:
    """Human-facing explanation for a risky RunBOM signal."""

    why: str
    fix: str | None = None
    note: str | None = None


def configure_runbom(
    policy_file: Path,
    command: str | RunbomDetectedCommand | None,
    *,
    force: bool = False,
) -> None:
    """Append or update the RunBOM section without changing static policy sections."""
    text = policy_file.read_text(encoding="utf-8") if policy_file.exists() else ""
    if not force and _existing_runbom_command(text):
        return
    command_text = _command_text(command)
    text = _remove_toml_table(text, "runbom").rstrip()
    if text:
        text += "\n\n"
    text += _runbom_toml(command_text)
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text(text.rstrip() + "\n", encoding="utf-8")


def detect_runbom_command(repo_root: Path) -> RunbomDetectedCommand | None:
    """Detect a simple runtime verification command without executing project code."""
    if (repo_root / "tests" / "agent_runtime").is_dir():
        return RunbomDetectedCommand(
            "python -m pytest tests/agent_runtime",
            "tests/agent_runtime directory exists",
        )
    if (repo_root / "tests" / "runbom").is_dir():
        return RunbomDetectedCommand(
            "python -m pytest tests/runbom",
            "tests/runbom directory exists",
        )
    if (repo_root / "tests").is_dir() and _has_pytest_project_signal(repo_root):
        return RunbomDetectedCommand(
            "python -m pytest",
            "tests directory exists with pytest project signals",
        )
    if _package_json_has_test_script(repo_root / "package.json"):
        if (repo_root / "pnpm-lock.yaml").is_file():
            return RunbomDetectedCommand("pnpm test", "package.json test script with pnpm lock")
        if (repo_root / "bun.lockb").is_file() or (repo_root / "bun.lock").is_file():
            return RunbomDetectedCommand("bun test", "package.json test script with bun lock")
        return RunbomDetectedCommand("npm test", "package.json test script")
    return None


def explain_runbom_command_detection(detected: RunbomDetectedCommand | None) -> str:
    if detected is None:
        return _runbom_setup_message()
    return f"RunBOM detected command: {detected.command}"


def run_runbom(config_path: Path | None = None) -> int:
    """Run the configured RunBOM command and write minimal JSONL lifecycle events."""
    if config_path is None:
        try:
            config_path = preferred_policy_path(Path.cwd())
        except ValueError as exc:
            print(f"aigenguard: {exc}", file=sys.stderr)
            return 1
    repo_root = config_path.parent.resolve()
    command, detected, config_error = _resolve_runbom_command(config_path, repo_root)
    if config_error:
        return 1
    if command is None:
        print(_runbom_setup_message(), file=sys.stderr)
        return 1
    if detected is not None:
        print(explain_runbom_command_detection(detected))

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        print(
            "RunBOM command could not be parsed: "
            f"{exc}. Configure a direct command like: pytest, python -m pytest, or npm test.",
            file=sys.stderr,
        )
        return 1
    if not argv:
        print(
            'RunBOM has no runtime command configured. Run: aigenguard activate --command "pytest"',
            file=sys.stderr,
        )
        return 1
    if _has_unsupported_shell_syntax(command):
        print(
            "RunBOM commands are executed without a shell. Configure a direct command like: "
            "pytest, python -m pytest, or npm test.",
            file=sys.stderr,
        )
        return 1

    output_dir = repo_root / ".agentbom"
    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = repo_root / RUNBOM_LOG
    started_at = time.time()
    _write_jsonl_event_path(
        jsonl_path,
        {
            "event": "run.start",
            "command": _redact_secret_text(command),
            "timestamp": started_at,
        },
        mode="w",
    )
    with tempfile.TemporaryDirectory(prefix="aigenguard-runbom-") as instrumentation_dir:
        instrumentation_path = Path(instrumentation_dir)
        (instrumentation_path / "sitecustomize.py").write_text(
            _sitecustomize_source(),
            encoding="utf-8",
        )
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH")
        pythonpath_parts = [str(instrumentation_path)]
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
        env["AGENTBOM_RUNBOM_EVENTS"] = str(jsonl_path)
        env["AGENTBOM_REPO_ROOT"] = str(repo_root)
        try:
            completed = subprocess.run(
                argv,
                cwd=repo_root,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            print(f"RunBOM command failed to start: {exc}", file=sys.stderr)
            exit_code = 1
        else:
            exit_code = completed.returncode
    ended_at = time.time()
    _write_jsonl_event_path(
        jsonl_path,
        {
            "event": "run.end",
            "command": _redact_secret_text(command),
            "exit_code": exit_code,
            "timestamp": ended_at,
            "duration_seconds": round(ended_at - started_at, 6),
        },
    )
    events = [normalize_runbom_event(event) for event in _read_jsonl_events(jsonl_path)]
    _write_jsonl_events_path(jsonl_path, events)
    summary = build_runbom_summary(
        events,
        command_exit_code=exit_code,
        command=command,
    )
    write_runbom_summary(repo_root / RUNBOM_SUMMARY, summary)

    if exit_code == 0:
        print("AigenGuard RunBOM OK")
    else:
        print("AigenGuard RunBOM FAILED")
        print(f"Runtime command failed with exit code {exit_code}")
    print("")
    print(format_runbom_terminal_summary(summary))
    return exit_code


def format_runbom_terminal_summary(summary: dict[str, Any]) -> str:
    """Format the human-readable RunBOM terminal summary."""
    lines = [
        "Runtime summary:",
        f"  {_summary_int(summary, 'events_total')} events observed",
        f"  {_summary_int(summary, 'unique_events')} unique events",
        f"  Highest risk: {str(summary.get('highest_risk') or 'low')}",
        "",
        "Top runtime signals:",
    ]
    signals = sort_top_runtime_signals(_summary_list(summary.get("risky_events")))[:5]
    if not signals:
        lines.append("  No high or critical runtime signals observed.")
    else:
        for signal in signals:
            explanation = explain_runbom_signal(signal)
            lines.append(f"  {_runtime_signal_title(signal)}")
            lines.append(f"       Why: {explanation.why}")
            if explanation.fix:
                lines.append(f"       Fix: {explanation.fix}")
            if explanation.note:
                lines.append(f"       Note: {explanation.note}")
            lines.append("")
        if lines[-1] == "":
            lines.pop()
    lines.extend(
        [
            "",
            "Artifacts:",
            f"  {RUNBOM_SUMMARY}",
            f"  {RUNBOM_LOG}",
        ]
    )
    return "\n".join(lines)


def sort_top_runtime_signals(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return high/critical runtime signals in stable review order."""
    signals = [_runtime_signal_event(event) for event in events]
    return sorted(
        (event for event in signals if str(event.get("risk") or "low") in {"critical", "high"}),
        key=_risky_event_sort_key,
    )


def explain_runbom_signal(event: dict[str, Any]) -> RunbomSignalExplanation:
    """Explain a risky runtime event without exposing secret values."""
    event_type = str(event.get("event") or "")
    tags = {str(tag) for tag in event.get("tags") or []}

    if event_type == "env.read":
        name = str(event.get("name") or "")
        if name in AI_PROVIDER_KEYS:
            return RunbomSignalExplanation(
                why="agent read an AI provider credential variable name.",
                note="secret value was not recorded.",
            )
        if name == "GITHUB_TOKEN":
            return RunbomSignalExplanation(
                why="agent read a GitHub token variable name.",
                fix="avoid exposing repository or CI tokens to agent runtime unless required.",
            )
        if name.startswith("AWS_"):
            return RunbomSignalExplanation(
                why="agent read a cloud credential variable name.",
                fix="avoid exposing cloud credentials to agent runtime unless explicitly required.",
            )
        if "secret-env" in tags:
            return RunbomSignalExplanation(
                why="agent read a credential-like environment variable name.",
                note="secret value was not recorded.",
            )

    if event_type == "filesystem.read":
        path = str(event.get("path") or "")
        if "secret-file" in tags or _path_name(path) == ".env":
            return RunbomSignalExplanation(
                why="agent read a common local secrets file.",
                fix="avoid reading local secrets files during agent runtime checks unless expected.",
            )
        if "git-config" in tags or _is_git_config_path(path):
            return RunbomSignalExplanation(
                why="agent read local Git repository configuration.",
                fix="verify the agent does not depend on local Git metadata unexpectedly.",
            )

    if event_type == "filesystem.write":
        path = str(event.get("path") or "")
        if "protected-workflow" in tags or _is_github_workflow_path(path):
            return RunbomSignalExplanation(
                why="agent wrote to GitHub Actions workflow configuration.",
                fix="review workflow changes carefully before commit.",
            )

    if event_type == "process.exec":
        basename = _process_basename(event)
        if basename in {"sh", "bash", "zsh"} or "shell-exec" in tags:
            return RunbomSignalExplanation(
                why="runtime evidence shows shell execution.",
                fix="remove shell execution or make it explicit and reviewed.",
            )
        if basename in {"curl", "wget", "nc", "ncat", "socat"} or "network-tool" in tags:
            return RunbomSignalExplanation(
                why="runtime evidence shows execution of a network-capable command-line tool.",
                fix="verify network access is expected.",
            )

    if event_type == "network.connect":
        host = str(event.get("host") or "")
        if host == "169.254.169.254" or "metadata-service" in tags:
            return RunbomSignalExplanation(
                why="runtime evidence shows a connection attempt to the cloud metadata service.",
                fix="block metadata service access unless explicitly required.",
            )
        if _is_rfc1918_host(host) or "private-network" in tags:
            return RunbomSignalExplanation(
                why="runtime evidence shows access to a private network address.",
                fix="verify this is expected in the runtime environment.",
            )

    return RunbomSignalExplanation(
        why="runtime evidence matched a high-risk signal.",
        fix="review whether this runtime behavior is expected.",
    )


def normalize_runbom_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a stable, sanitized RunBOM event shape."""
    event_type = str(event.get("event") or "")
    normalized: dict[str, Any] = {"event": event_type}
    if event_type in {"run.start", "run.end"}:
        if "command" in event:
            normalized["command"] = _redact_secret_text(str(event.get("command") or ""))
        if "exit_code" in event:
            normalized["exit_code"] = _json_safe_scalar(event.get("exit_code"))
        if "duration_seconds" in event:
            normalized["duration_seconds"] = _json_safe_scalar(event.get("duration_seconds"))
        if "timestamp" in event:
            normalized["timestamp"] = _json_safe_scalar(event.get("timestamp"))
        normalized.update(classify_runbom_event(normalized))
        return normalized

    if event_type in {"filesystem.read", "filesystem.write"}:
        normalized["path"] = str(event.get("path") or "")
        if "mode" in event:
            normalized["mode"] = str(event.get("mode") or "")
        if "method" in event:
            normalized["method"] = str(event.get("method") or "")
    elif event_type == "env.read":
        normalized["name"] = str(event.get("name") or "")
    elif event_type == "process.exec":
        argv = event.get("argv")
        normalized["argv"] = _normalize_argv(argv)
        executable = event.get("executable")
        if executable:
            normalized["executable"] = _redact_secret_text(str(executable))
    elif event_type == "network.connect":
        normalized["host"] = str(event.get("host") or "")
        if "port" in event:
            normalized["port"] = _json_safe_scalar(event.get("port"))
    else:
        for key in sorted(event):
            if key in {"event", "value", "secret", "env_value"}:
                continue
            normalized[key] = _json_safe_scalar(event[key])

    if "timestamp" in event:
        normalized["timestamp"] = _json_safe_scalar(event.get("timestamp"))
    normalized.update(classify_runbom_event(normalized))
    return normalized


def classify_runbom_event(event: dict[str, Any]) -> dict[str, Any]:
    """Classify a normalized event for summary-only risk reporting."""
    risk = "low"
    tags: list[str] = []
    event_type = str(event.get("event") or "")

    if event_type in {"filesystem.read", "filesystem.write"}:
        path = str(event.get("path") or "")
        path_name = _path_name(path)
        if _is_ssh_path(path):
            risk = _max_risk(risk, "critical")
            _add_tags(tags, "ssh-material", "protected-path")
        if event_type == "filesystem.read" and (path_name == ".env" or path_name.startswith(".env.")):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-file", "protected-path")
        if event_type == "filesystem.read" and _is_git_config_path(path):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "git-config", "protected-path")
        if event_type == "filesystem.write" and _is_github_workflow_path(path):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "protected-workflow")

    elif event_type == "env.read":
        name = str(event.get("name") or "")
        if name == "GITHUB_TOKEN":
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-env", "github-token")
        if name.startswith("AWS_"):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-env", "cloud-credential")
        if name.startswith("SSH_"):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-env", "ssh-material")
        if name.endswith(("_SECRET", "_TOKEN", "_PRIVATE_KEY")):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-env")
        if name in AI_PROVIDER_KEYS:
            risk = _max_risk(risk, "high")
            _add_tags(tags, "secret-env", "ai-provider-key")

    elif event_type == "process.exec":
        basename = _process_basename(event)
        if basename in {"sh", "bash", "zsh"}:
            risk = _max_risk(risk, "high")
            _add_tags(tags, "shell-exec")
        if basename in {"curl", "wget", "nc", "ncat", "socat"}:
            risk = _max_risk(risk, "high")
            _add_tags(tags, "network-tool")

    elif event_type == "network.connect":
        host = str(event.get("host") or "")
        if host == "169.254.169.254":
            risk = _max_risk(risk, "critical")
            _add_tags(tags, "metadata-service")
        elif _is_rfc1918_host(host):
            risk = _max_risk(risk, "high")
            _add_tags(tags, "private-network")

    return {"risk": risk, "tags": tags}


def runbom_event_identity(event: dict[str, Any]) -> tuple[Any, ...]:
    event_type = str(event.get("event") or "")
    risk = str(event.get("risk") or "low")
    tags = tuple(str(tag) for tag in event.get("tags") or [])
    if event_type in {"filesystem.read", "filesystem.write"}:
        return (event_type, str(event.get("path") or ""), risk, tags)
    if event_type == "env.read":
        return (event_type, str(event.get("name") or ""), risk, tags)
    if event_type == "process.exec":
        argv = tuple(str(arg) for arg in event.get("argv") or [])
        return (event_type, str(event.get("executable") or ""), argv, risk, tags)
    if event_type == "network.connect":
        return (
            event_type,
            str(event.get("host") or ""),
            _json_safe_scalar(event.get("port")),
            risk,
            tags,
        )
    return (event_type, risk, tags)


def build_runbom_summary(
    events: list[dict[str, Any]],
    command_exit_code: int,
    command: str,
) -> dict[str, Any]:
    normalized_events = [normalize_runbom_event(event) for event in events]
    runtime_events = [
        event for event in normalized_events if event.get("event") in RUNTIME_EVENT_TYPES
    ]
    unique_events: dict[tuple[Any, ...], dict[str, Any]] = {}
    for event in runtime_events:
        unique_events.setdefault(runbom_event_identity(event), event)

    unique_runtime_events = list(unique_events.values())
    risk_counts = {risk: 0 for risk in RISK_LEVELS}
    event_types = {event_type: 0 for event_type in RUNTIME_EVENT_TYPES}
    highest_risk = "low"
    risky_events: list[dict[str, Any]] = []
    for event in unique_runtime_events:
        event_type = str(event.get("event") or "")
        risk = str(event.get("risk") or "low")
        if event_type in event_types:
            event_types[event_type] += 1
        if risk in risk_counts:
            risk_counts[risk] += 1
        highest_risk = _max_risk(highest_risk, risk)
        if risk in {"high", "critical"}:
            risky_events.append(_summary_event(event))

    risky_events.sort(key=_risky_event_sort_key)
    return {
        "schema_version": "runbom.summary.v1",
        "command": _redact_secret_text(command),
        "command_exit_code": command_exit_code,
        "events_total": len(runtime_events),
        "unique_events": len(unique_runtime_events),
        "highest_risk": highest_risk,
        "risk_counts": risk_counts,
        "event_types": event_types,
        "risky_events": risky_events,
    }


def write_runbom_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def _resolve_runbom_command(
    config_path: Path,
    repo_root: Path,
) -> tuple[str | None, RunbomDetectedCommand | None, bool]:
    if config_path.exists():
        try:
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            print(f"aigenguard: {exc}", file=sys.stderr)
            return None, None, True
        runbom = config.get("runbom")
        if isinstance(runbom, dict) and runbom.get("enabled") is True:
            command = str(runbom.get("command") or "").strip()
            if command:
                return command, None, False

    detected = detect_runbom_command(repo_root)
    if detected is None:
        return None, None, False
    return detected.command, detected, False


def _runbom_toml(command: str) -> str:
    return "\n".join(
        [
            "[runbom]",
            f"enabled = {_toml_bool(bool(command))}",
            'preset = "safe"',
            f"command = {_toml_string(command)}",
            f"baseline = {_toml_string(RUNBOM_BASELINE)}",
            'fail_on_new = "high"',
        ]
    )


def _command_text(command: str | RunbomDetectedCommand | None) -> str:
    if command is None:
        return ""
    if isinstance(command, RunbomDetectedCommand):
        return command.command
    return str(command).strip()


def _existing_runbom_command(text: str) -> str:
    if not text.strip():
        return ""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return ""
    runbom = data.get("runbom")
    if not isinstance(runbom, dict):
        return ""
    return str(runbom.get("command") or "").strip()


def _runbom_setup_message() -> str:
    return "\n".join(
        [
            "RunBOM is not configured yet.",
            "",
            "Run one of:",
            "  aigenguard activate",
            '  aigenguard activate --command "python -m pytest"',
            "",
            "Recommended:",
            "  create tests/agent_runtime/ and run aigenguard activate again",
        ]
    )


def _has_pytest_project_signal(repo_root: Path) -> bool:
    if (repo_root / "pytest.ini").is_file():
        return True
    pyproject = _read_small_text(repo_root / "pyproject.toml")
    if pyproject and "[tool.pytest" in pyproject:
        return True
    tox = _read_small_text(repo_root / "tox.ini")
    if tox and ("[pytest]" in tox or "[tool:pytest]" in tox):
        return True
    requirements = _read_small_text(repo_root / "requirements.txt")
    if requirements and _mentions_pytest(requirements):
        return True
    requirements_dev = _read_small_text(repo_root / "requirements-dev.txt")
    if requirements_dev and _mentions_pytest(requirements_dev):
        return True
    return (repo_root / "uv.lock").is_file() and _appears_python_project(repo_root)


def _mentions_pytest(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("pytest"):
            return True
    return False


def _appears_python_project(repo_root: Path) -> bool:
    if (repo_root / "pyproject.toml").is_file():
        return True
    if (repo_root / "setup.py").is_file() or (repo_root / "setup.cfg").is_file():
        return True
    if (repo_root / "requirements.txt").is_file() or (repo_root / "requirements-dev.txt").is_file():
        return True
    try:
        return any(path.suffix == ".py" and path.is_file() for path in repo_root.iterdir())
    except OSError:
        return False


def _has_unsupported_shell_syntax(command: str) -> bool:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens = list(lexer)
    unsupported = {"&", "&&", "|", "||", ";", "<", "<<", ">", ">>"}
    if any(token in unsupported for token in tokens):
        return True
    if any(
        token == "$" and next_token == "(" for token, next_token in zip(tokens, tokens[1:])
    ):
        return True
    return any("`" in token for token in tokens)


def _package_json_has_test_script(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        text = _read_small_text(path)
        if text is None:
            return False
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    scripts = data.get("scripts")
    return isinstance(scripts, dict) and isinstance(scripts.get("test"), str)


def _read_small_text(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > 1_000_000:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _remove_toml_table(text: str, table: str) -> str:
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"[{table}]":
            start = index
            break
    if start is None:
        return text

    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = index
            break
    del lines[start:end]
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def _write_jsonl_event(handle: TextIO, event: dict[str, object]) -> None:
    handle.write(json.dumps(event, sort_keys=True) + "\n")
    handle.flush()


def _write_jsonl_event_path(
    path: Path, event: dict[str, object], mode: str = "a"
) -> None:
    with path.open(mode, encoding="utf-8") as handle:
        _write_jsonl_event(handle, event)


def _read_jsonl_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return events
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _write_jsonl_events_path(path: Path, events: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            _write_jsonl_event(handle, event)


def _json_safe_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _normalize_argv(argv: Any) -> list[str]:
    if isinstance(argv, (list, tuple)):
        return [_redact_secret_text(str(arg)) for arg in argv]
    if argv is None:
        return []
    return [_redact_secret_text(str(argv))]


def _path_name(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def _is_ssh_path(path: str) -> bool:
    normalized = path.replace("\\", "/").rstrip("/")
    return (
        normalized == "~/.ssh"
        or normalized.startswith("~/.ssh/")
        or normalized.endswith("/.ssh")
        or "/.ssh/" in normalized
    )


def _is_git_config_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip("/")
    return normalized == ".git/config" or normalized.endswith("/.git/config")


def _is_github_workflow_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("/")
    return normalized.startswith(".github/workflows/") or "/.github/workflows/" in normalized


def _max_risk(left: str, right: str) -> str:
    if right not in RISK_LEVELS:
        return left if left in RISK_LEVELS else "low"
    if left not in RISK_LEVELS:
        return right
    return right if RISK_LEVELS.index(right) > RISK_LEVELS.index(left) else left


def _add_tags(tags: list[str], *new_tags: str) -> None:
    for tag in new_tags:
        if tag not in tags:
            tags.append(tag)


def _process_basename(event: dict[str, Any]) -> str:
    executable = str(event.get("executable") or "")
    if not executable:
        argv = event.get("argv")
        if isinstance(argv, list) and argv:
            executable = str(argv[0])
    return executable.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _is_rfc1918_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def _summary_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("event") or "")
    summary: dict[str, Any] = {"event": event_type}
    if event_type in {"filesystem.read", "filesystem.write"}:
        summary["path"] = str(event.get("path") or "")
    elif event_type == "env.read":
        summary["name"] = str(event.get("name") or "")
    elif event_type == "process.exec":
        if event.get("executable"):
            summary["executable"] = str(event.get("executable"))
        summary["argv"] = [str(arg) for arg in event.get("argv") or []]
    elif event_type == "network.connect":
        summary["host"] = str(event.get("host") or "")
        if "port" in event:
            summary["port"] = _json_safe_scalar(event.get("port"))
    summary["risk"] = str(event.get("risk") or "low")
    summary["tags"] = [str(tag) for tag in event.get("tags") or []]
    return summary


def _summary_int(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    return value if isinstance(value, int) else 0


def _summary_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _runtime_signal_event(event: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_runbom_event(event)
    risk = str(event.get("risk") or "")
    if risk in RISK_LEVELS:
        normalized["risk"] = risk
    tags = event.get("tags")
    if isinstance(tags, list):
        normalized["tags"] = [str(tag) for tag in tags]
    return normalized


def _runtime_signal_title(event: dict[str, Any]) -> str:
    risk = str(event.get("risk") or "low").upper()
    event_type = str(event.get("event") or "")
    target = _runtime_signal_target(event)
    return f"{risk} {event_type} {target}".rstrip()


def _runtime_signal_target(event: dict[str, Any]) -> str:
    event_type = str(event.get("event") or "")
    if event_type in {"filesystem.read", "filesystem.write"}:
        return str(event.get("path") or "")
    if event_type == "env.read":
        return str(event.get("name") or "")
    if event_type == "process.exec":
        return _process_basename(event)
    if event_type == "network.connect":
        return str(event.get("host") or "")
    return ""


def _risky_event_sort_key(event: dict[str, Any]) -> tuple[Any, ...]:
    risk = str(event.get("risk") or "low")
    risk_rank = RISK_LEVELS.index(risk) if risk in RISK_LEVELS else 0
    return (
        -risk_rank,
        str(event.get("event") or ""),
        str(event.get("path") or event.get("name") or event.get("host") or ""),
        str(event.get("port") or ""),
        tuple(str(arg) for arg in event.get("argv") or []),
        tuple(str(tag) for tag in event.get("tags") or []),
    )


def _sitecustomize_source() -> str:
    return r'''
from __future__ import annotations

import builtins
import json
import os
import pathlib
import socket
import subprocess
import threading
import time


_EVENTS_PATH = os.environ.get("AGENTBOM_RUNBOM_EVENTS")
_REPO_ROOT = os.environ.get("AGENTBOM_REPO_ROOT") or os.getcwd()
_HOME = os.path.expanduser("~")
_ORIGINAL_OPEN = builtins.open
_ORIGINAL_PATH_READ_TEXT = pathlib.Path.read_text
_ORIGINAL_PATH_READ_BYTES = pathlib.Path.read_bytes
_ORIGINAL_PATH_WRITE_TEXT = pathlib.Path.write_text
_ORIGINAL_PATH_WRITE_BYTES = pathlib.Path.write_bytes
_ORIGINAL_SUBPROCESS_RUN = subprocess.run
_ORIGINAL_SUBPROCESS_POPEN = subprocess.Popen
_ORIGINAL_OS_SYSTEM = os.system
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_GETENV = os.getenv
_ENVIRON_CLASS = type(os.environ)
_ORIGINAL_ENVIRON_GET = _ENVIRON_CLASS.get
_ORIGINAL_ENVIRON_GETITEM = _ENVIRON_CLASS.__getitem__
_STATE = threading.local()


def _emit(event):
    if not _EVENTS_PATH:
        return
    try:
        event["timestamp"] = time.time()
        line = json.dumps(event, sort_keys=True) + "\n"
        with _ORIGINAL_OPEN(_EVENTS_PATH, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
    except Exception:
        pass


def _safe_path(path):
    try:
        raw = os.fspath(path)
    except TypeError:
        return repr(path)
    try:
        absolute = os.path.abspath(raw)
        repo_root = os.path.abspath(_REPO_ROOT)
        relative = os.path.relpath(absolute, repo_root)
        if relative == "." or not relative.startswith(".." + os.sep) and relative != "..":
            return relative
        if _HOME and absolute == _HOME:
            return "~"
        if _HOME and absolute.startswith(_HOME + os.sep):
            return "~" + absolute[len(_HOME):]
        return absolute
    except Exception:
        return raw


def _mode_events(mode):
    mode = "r" if mode is None else str(mode)
    events = []
    if any(flag in mode for flag in ("r", "+")):
        events.append("filesystem.read")
    if any(flag in mode for flag in ("w", "a", "x", "+")):
        events.append("filesystem.write")
    return events


def _emit_file_events(path, mode):
    safe_path = _safe_path(path)
    for event_name in _mode_events(mode):
        _emit({"event": event_name, "path": safe_path, "mode": str(mode)})


def _argv_list(args):
    if isinstance(args, (list, tuple)):
        return [_redact_arg(item) for item in args]
    return [_redact_arg(args)]


def _redact_arg(arg):
    text = os.fsdecode(arg) if isinstance(arg, bytes) else str(arg)
    lowered = text.lower()
    secret_names = (
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "access_key",
        "secret_key",
        "private_key",
    )
    if any(name in lowered for name in secret_names):
        if "=" in text:
            return text.split("=", 1)[0] + "=<redacted>"
        return "<redacted>"
    return text


def _emit_process(args):
    _emit({"event": "process.exec", "argv": _argv_list(args)})


def _network_target(address):
    try:
        host, port = address[:2]
    except Exception:
        host, port = str(address), None
    return {"host": str(host), "port": port}


def _emit_network(address):
    event = {"event": "network.connect"}
    event.update(_network_target(address))
    _emit(event)


def _env_name(name):
    try:
        return os.fsdecode(name)
    except (TypeError, ValueError):
        return str(name)


def _emit_env(name):
    _emit({"event": "env.read", "name": _env_name(name)})


def open_hook(file, mode="r", *args, **kwargs):
    _emit_file_events(file, mode)
    return _ORIGINAL_OPEN(file, mode, *args, **kwargs)


def path_read_text_hook(self, *args, **kwargs):
    _emit({"event": "filesystem.read", "path": _safe_path(self), "method": "Path.read_text"})
    return _ORIGINAL_PATH_READ_TEXT(self, *args, **kwargs)


def path_read_bytes_hook(self, *args, **kwargs):
    _emit({"event": "filesystem.read", "path": _safe_path(self), "method": "Path.read_bytes"})
    return _ORIGINAL_PATH_READ_BYTES(self, *args, **kwargs)


def path_write_text_hook(self, *args, **kwargs):
    _emit({"event": "filesystem.write", "path": _safe_path(self), "method": "Path.write_text"})
    return _ORIGINAL_PATH_WRITE_TEXT(self, *args, **kwargs)


def path_write_bytes_hook(self, *args, **kwargs):
    _emit({"event": "filesystem.write", "path": _safe_path(self), "method": "Path.write_bytes"})
    return _ORIGINAL_PATH_WRITE_BYTES(self, *args, **kwargs)


def subprocess_run_hook(args, *popenargs, **kwargs):
    _emit_process(args)
    previous = getattr(_STATE, "suppress_popen", False)
    _STATE.suppress_popen = True
    try:
        return _ORIGINAL_SUBPROCESS_RUN(args, *popenargs, **kwargs)
    finally:
        _STATE.suppress_popen = previous


class PopenHook(_ORIGINAL_SUBPROCESS_POPEN):
    def __init__(self, args, *popenargs, **kwargs):
        if not getattr(_STATE, "suppress_popen", False):
            _emit_process(args)
        super().__init__(args, *popenargs, **kwargs)


def os_system_hook(command):
    _emit_process([command])
    return _ORIGINAL_OS_SYSTEM(command)


def create_connection_hook(address, *args, **kwargs):
    _emit_network(address)
    return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)


def socket_connect_hook(self, address):
    _emit_network(address)
    return _ORIGINAL_SOCKET_CONNECT(self, address)


def getenv_hook(key, default=None):
    _emit_env(key)
    try:
        return _ORIGINAL_ENVIRON_GET(os.environ, key, default)
    except Exception:
        return _ORIGINAL_GETENV(key, default)


def environ_get_hook(self, key, default=None):
    _emit_env(key)
    return _ORIGINAL_ENVIRON_GET(self, key, default)


def environ_getitem_hook(self, key):
    _emit_env(key)
    return _ORIGINAL_ENVIRON_GETITEM(self, key)


try:
    builtins.open = open_hook
    pathlib.Path.read_text = path_read_text_hook
    pathlib.Path.read_bytes = path_read_bytes_hook
    pathlib.Path.write_text = path_write_text_hook
    pathlib.Path.write_bytes = path_write_bytes_hook
    subprocess.run = subprocess_run_hook
    subprocess.Popen = PopenHook
    os.system = os_system_hook
    socket.create_connection = create_connection_hook
    socket.socket.connect = socket_connect_hook
    os.getenv = getenv_hook
    _ENVIRON_CLASS.get = environ_get_hook
    _ENVIRON_CLASS.__getitem__ = environ_getitem_hook
except Exception:
    pass
'''


def _redact_secret_text(value: str) -> str:
    lowered = value.lower()
    secret_names = (
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "access_key",
        "secret_key",
        "private_key",
    )
    if any(name in lowered for name in secret_names):
        return "<redacted>"
    return value


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _toml_string(value: str) -> str:
    return json.dumps(value)
