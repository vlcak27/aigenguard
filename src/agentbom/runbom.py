"""Experimental RunBOM configuration and runtime command support."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import TextIO


RUNBOM_BASELINE = ".agentbom/runbom-baseline.json"
RUNBOM_LOG = ".agentbom/runbom.jsonl"


def configure_runbom(policy_file: Path, command: str) -> None:
    """Append or update the RunBOM section without changing static policy sections."""
    text = policy_file.read_text(encoding="utf-8") if policy_file.exists() else ""
    text = _remove_toml_table(text, "runbom").rstrip()
    if text:
        text += "\n\n"
    text += _runbom_toml(command)
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text(text.rstrip() + "\n", encoding="utf-8")


def detect_runbom_command(repo_root: Path) -> str:
    """Detect a simple runtime verification command without executing project code."""
    if (repo_root / "tests" / "agent_runtime").is_dir():
        return "pytest tests/agent_runtime"
    if _has_pytest_project(repo_root):
        return "pytest"
    if _has_python_pytest_dependency(repo_root):
        return "python -m pytest"
    if _package_json_has_test_script(repo_root / "package.json"):
        if (repo_root / "pnpm-lock.yaml").is_file():
            return "pnpm test"
        if (repo_root / "bun.lockb").is_file() or (repo_root / "bun.lock").is_file():
            return "bun test"
        return "npm test"
    return ""


def run_runbom(config_path: Path = Path("agentbom.toml")) -> int:
    """Run the configured RunBOM command and write minimal JSONL lifecycle events."""
    repo_root = config_path.parent.resolve()
    if not config_path.exists():
        print("RunBOM is not configured. Run: agentbom activate", file=sys.stderr)
        return 1
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"agentbom: {exc}", file=sys.stderr)
        return 1

    runbom = config.get("runbom")
    if not isinstance(runbom, dict) or runbom.get("enabled") is not True:
        print(
            'RunBOM is not enabled. Run: agentbom activate --command "pytest"',
            file=sys.stderr,
        )
        return 1

    command = str(runbom.get("command") or "").strip()
    if not command:
        print(
            'RunBOM has no runtime command configured. Run: agentbom activate --command "pytest"',
            file=sys.stderr,
        )
        return 1
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
            'RunBOM has no runtime command configured. Run: agentbom activate --command "pytest"',
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
    with jsonl_path.open("w", encoding="utf-8") as handle:
        _write_jsonl_event(
            handle,
            {
                "event": "run.start",
                "command": command,
                "timestamp": started_at,
            },
        )
        try:
            completed = subprocess.run(argv, cwd=repo_root)
        except OSError as exc:
            print(f"RunBOM command failed to start: {exc}", file=sys.stderr)
            exit_code = 1
        else:
            exit_code = completed.returncode
        ended_at = time.time()
        _write_jsonl_event(
            handle,
            {
                "event": "run.end",
                "command": command,
                "exit_code": exit_code,
                "timestamp": ended_at,
                "duration_seconds": round(ended_at - started_at, 6),
            },
        )

    if exit_code == 0:
        print("AgentBOM RunBOM OK")
    else:
        print("AgentBOM RunBOM FAILED")
    return exit_code


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


def _has_pytest_project(repo_root: Path) -> bool:
    if (repo_root / "tests").is_dir():
        return True
    if (repo_root / "pytest.ini").is_file() or (repo_root / ".pytest.ini").is_file():
        return True
    pyproject = _read_small_text(repo_root / "pyproject.toml")
    if pyproject and "[tool.pytest" in pyproject:
        return True
    for name in ("tox.ini", "setup.cfg"):
        text = _read_small_text(repo_root / name)
        if text and ("[pytest]" in text or "[tool:pytest]" in text):
            return True
    return False


def _has_python_pytest_dependency(repo_root: Path) -> bool:
    pyproject = _read_small_text(repo_root / "pyproject.toml")
    if pyproject and "pytest" in pyproject:
        return True
    requirements = _read_small_text(repo_root / "requirements-dev.txt")
    if requirements and _mentions_pytest(requirements):
        return True
    requirements = _read_small_text(repo_root / "requirements.txt")
    return bool(requirements and _mentions_pytest(requirements))


def _mentions_pytest(text: str) -> bool:
    return any(line.strip().startswith("pytest") for line in text.splitlines())


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


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _toml_string(value: str) -> str:
    return json.dumps(value)
