"""Experimental RunBOM configuration and runtime command support."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
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
    _write_jsonl_event_path(
        jsonl_path,
        {
            "event": "run.start",
            "command": _redact_secret_text(command),
            "timestamp": started_at,
        },
        mode="w",
    )
    with tempfile.TemporaryDirectory(prefix="agentbom-runbom-") as instrumentation_dir:
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
            completed = subprocess.run(argv, cwd=repo_root, env=env)
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


def _write_jsonl_event_path(
    path: Path, event: dict[str, object], mode: str = "a"
) -> None:
    with path.open(mode, encoding="utf-8") as handle:
        _write_jsonl_event(handle, event)


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
