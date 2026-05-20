"""Local pre-commit guard support for AgentBOM."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Mapping, TextIO

from .report import write_reports
from .scanner import scan_path


GUARD_MODES = ("advisory", "confirm", "enforce")
MANAGED_BEGIN = "# BEGIN AgentBOM managed block"
MANAGED_END = "# END AgentBOM managed block"

ConfirmReader = Callable[[str], bool | None]


class ExistingHookError(ValueError):
    """Raised when a pre-existing non-AgentBOM hook would be changed implicitly."""


@dataclass(frozen=True)
class LocalGuardStatus:
    repository_detected: bool
    repo_root: Path | None
    policy: str | None
    policy_exists: bool
    hook_path: Path | None
    hook_installed: bool
    mode: str | None


def run_guard(
    path: str | Path,
    policy_path: str | Path,
    mode: str,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    confirm_reader: ConfirmReader | None = None,
) -> int:
    """Run the concise local policy guard."""
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    env = os.environ if environ is None else environ
    guard_mode = normalize_guard_mode(mode)

    try:
        with tempfile.TemporaryDirectory(prefix="agentbom-guard-") as output_dir:
            bom = scan_path(
                path,
                policy_path=policy_path,
                enforce_policy=guard_mode == "enforce",
            )
            write_reports(bom, Path(output_dir))
    except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as exc:
        print(f"agentbom: {exc}", file=err)
        return 1

    policy_review = bom.get("policy_review")
    if not isinstance(policy_review, dict):
        print("agentbom: guard requires an AgentBOM TOML policy file.", file=err)
        return 1

    violations = _policy_items(policy_review.get("violations"))
    warnings = _policy_items(policy_review.get("warnings"))

    if not violations and not warnings:
        _print_guard_status("AgentBOM OK", "green", out, env)
        print("No policy violations found.", file=out)
        return 0

    if not violations:
        _print_guard_status("AgentBOM passed with warnings", "yellow", out, env)
        print("", file=out)
        _print_policy_items(warnings, out, env)
        print("Commit allowed.", file=out)
        return 0

    if guard_mode == "advisory":
        _print_guard_status("AgentBOM found policy violations", "yellow", out, env)
        print("", file=out)
        _print_policy_items(violations, out, env)
        print("Commit allowed because guard mode is advisory.", file=out)
        print("", file=out)
        print("To block commits, run:", file=out)
        print("  agentbom install-hook --policy agentbom.toml --mode enforce", file=out)
        return 0

    if guard_mode == "confirm":
        _print_guard_status("AgentBOM found policy violations", "yellow", out, env)
        print("", file=out)
        _print_policy_items(violations, out, env)
        reader = _read_confirmation_from_tty if confirm_reader is None else confirm_reader
        answer = reader("Continue with commit? [y/N]: ")
        if answer is None:
            print("agentbom confirm mode requires an interactive terminal.", file=out)
            print(
                "Commit blocked. Use advisory mode, enforce mode, or bypass intentionally.",
                file=out,
            )
            return 1
        if answer:
            print("Commit allowed.", file=out)
            return 0
        print("Commit blocked.", file=out)
        return 1

    _print_guard_status("AgentBOM blocked this commit", "red", out, env)
    print("", file=out)
    _print_policy_items(violations, out, env)
    print("", file=out)
    print("Fix violations or bypass locally with:", file=out)
    print("  AGENTBOM_SKIP_HOOK=1 git commit", file=out)
    print("  git commit --no-verify", file=out)
    return 1


def install_hook(
    policy_path: str | Path,
    mode: str,
    *,
    agentbom_command: str = "agentbom",
    append: bool = False,
    force: bool = False,
    cwd: str | Path | None = None,
) -> Path:
    """Install or replace the AgentBOM managed pre-commit hook block."""
    guard_mode = normalize_guard_mode(mode)
    _, git_dir = find_git_root(cwd)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    existing = hook_path.read_text(encoding="utf-8") if hook_path.exists() else ""
    block = render_hook_block(
        policy_path=policy_path,
        mode=guard_mode,
        agentbom_command=agentbom_command,
    )
    hook_path.write_text(
        _install_managed_block(existing, block, append=append, force=force),
        encoding="utf-8",
    )
    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path


def uninstall_hook(*, cwd: str | Path | None = None) -> Path | None:
    """Remove the AgentBOM managed pre-commit hook block."""
    _, git_dir = find_git_root(cwd)
    hook_path = git_dir / "hooks" / "pre-commit"
    if not hook_path.exists():
        return None
    existing = hook_path.read_text(encoding="utf-8")
    updated = _remove_managed_block(existing)
    if updated is None:
        return None
    if updated.strip() in {"", "#!/bin/sh"}:
        hook_path.unlink()
        return hook_path
    hook_path.write_text(updated, encoding="utf-8")
    return hook_path


def local_guard_status(
    *,
    policy_path: str | Path = "agentbom.toml",
    cwd: str | Path | None = None,
) -> LocalGuardStatus:
    try:
        repo_root, git_dir = find_git_root(cwd)
    except (FileNotFoundError, ValueError):
        return LocalGuardStatus(
            repository_detected=False,
            repo_root=None,
            policy=None,
            policy_exists=False,
            hook_path=None,
            hook_installed=False,
            mode=None,
        )

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_policy = None
    mode = None
    hook_installed = False
    if hook_path.exists():
        try:
            text = hook_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        if text:
            metadata = parse_managed_hook(text)
            hook_installed = metadata is not None
            if metadata is not None:
                hook_policy = metadata.get("policy")
                mode = metadata.get("mode")

    policy = hook_policy or str(policy_path)
    policy_file = Path(policy)
    if not policy_file.is_absolute():
        policy_file = repo_root / policy_file

    return LocalGuardStatus(
        repository_detected=True,
        repo_root=repo_root,
        policy=policy,
        policy_exists=policy_file.is_file(),
        hook_path=hook_path,
        hook_installed=hook_installed,
        mode=mode,
    )


def has_unmanaged_hook(*, cwd: str | Path | None = None) -> bool:
    """Return true when a non-empty pre-commit hook has no AgentBOM block."""
    _, git_dir = find_git_root(cwd)
    hook_path = git_dir / "hooks" / "pre-commit"
    if not hook_path.exists():
        return False
    try:
        text = hook_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    return bool(text.strip()) and MANAGED_BEGIN not in text and MANAGED_END not in text


def parse_managed_hook(text: str) -> dict[str, str] | None:
    if MANAGED_BEGIN not in text or MANAGED_END not in text:
        return None
    for line in text.splitlines():
        if " guard " not in line or " --policy " not in line or " --mode " not in line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if "guard" not in parts:
            continue
        guard_index = parts.index("guard")
        command = parts[guard_index:]
        metadata = _hook_command_metadata(command)
        if metadata is not None:
            return metadata
    return {}


def render_hook_block(
    *,
    policy_path: str | Path,
    mode: str,
    agentbom_command: str = "agentbom",
) -> str:
    """Render the repo-local managed hook block."""
    guard_mode = normalize_guard_mode(mode)
    policy = str(policy_path)
    policy_word = _shell_double_quote(policy)
    policy_message = _shell_double_quote_content(policy)
    mode_word = _shell_double_quote(guard_mode)
    command_word = shlex.quote(agentbom_command)
    return "\n".join(
        [
            MANAGED_BEGIN,
            'if [ "${AGENTBOM_SKIP_HOOK:-}" = "1" ]; then',
            '  echo "AgentBOM policy guard skipped by AGENTBOM_SKIP_HOOK=1"',
            "  exit 0",
            "fi",
            "",
            "repo_root=$(git rev-parse --show-toplevel 2>/dev/null)",
            'if [ -z "$repo_root" ]; then',
            '  echo "AgentBOM policy guard could not find repository root." >&2',
            "  exit 1",
            "fi",
            'cd "$repo_root" || exit 1',
            "",
            f"if [ ! -f {policy_word} ]; then",
            f"  echo \"AgentBOM policy guard could not find policy file: {policy_message}\" >&2",
            "  exit 1",
            "fi",
            "",
            f"{command_word} guard . --policy {policy_word} --mode {mode_word}",
            "agentbom_status=$?",
            'if [ "$agentbom_status" -ne 0 ]; then',
            '  exit "$agentbom_status"',
            "fi",
            MANAGED_END,
        ]
    )


def find_git_root(cwd: str | Path | None = None) -> tuple[Path, Path]:
    """Find a repository root with a local .git directory."""
    current = Path.cwd() if cwd is None else Path(cwd)
    current = current.resolve()
    for candidate in (current, *current.parents):
        git_path = candidate / ".git"
        if git_path.is_dir():
            return candidate, git_path
        if git_path.is_file():
            raise ValueError(
                "repo-local hook install requires a .git directory; "
                f"unsupported git file: {git_path}"
            )
    raise FileNotFoundError("could not find .git directory; run inside a Git repository")


def normalize_guard_mode(mode: str) -> str:
    if mode not in GUARD_MODES:
        modes = ", ".join(GUARD_MODES)
        raise ValueError(f"invalid guard mode: {mode}; choose one of {modes}")
    return mode


def _install_managed_block(
    existing: str,
    block: str,
    *,
    append: bool,
    force: bool,
) -> str:
    updated = _remove_managed_block(existing)
    if updated is None and existing.strip():
        if force:
            return f"#!/bin/sh\n\n{block}\n"
        if not append:
            raise ExistingHookError("existing non-AgentBOM pre-commit hook found")
    if updated is None:
        updated = existing
    updated = updated.rstrip()
    if not updated:
        return f"#!/bin/sh\n\n{block}\n"
    if not updated.startswith("#!"):
        updated = f"#!/bin/sh\n\n{updated}"
    return f"{updated}\n\n{block}\n"


def _remove_managed_block(existing: str) -> str | None:
    start = existing.find(MANAGED_BEGIN)
    end = existing.find(MANAGED_END)
    if start == -1 and end == -1:
        return None
    if start == -1 or end == -1 or end < start:
        raise ValueError("found an incomplete AgentBOM managed hook block")
    end += len(MANAGED_END)
    if end < len(existing) and existing[end] == "\n":
        end += 1
    updated = existing[:start].rstrip() + "\n\n" + existing[end:].lstrip("\n")
    return updated.rstrip() + "\n" if updated.strip() else ""


def _read_confirmation_from_tty(prompt: str) -> bool | None:
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            answer = tty.readline()
    except OSError:
        return None
    return answer.strip().lower() in {"y", "yes"}


def _hook_command_metadata(command: list[str]) -> dict[str, str] | None:
    if len(command) < 2 or command[0] != "guard":
        return None
    metadata = {}
    for name, key in (("--policy", "policy"), ("--mode", "mode")):
        if name not in command:
            continue
        index = command.index(name)
        if index + 1 < len(command):
            metadata[key] = command[index + 1]
    return metadata


def _policy_items(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _print_guard_status(
    message: str,
    color: str,
    stdout: TextIO,
    environ: Mapping[str, str],
) -> None:
    print(_color(message, color, stdout, environ), file=stdout)


def _print_policy_items(
    items: list[dict[str, object]],
    stdout: TextIO,
    environ: Mapping[str, str],
) -> None:
    for item in items[:3]:
        severity = str(item.get("severity", "low"))
        severity_label = _format_severity(severity, stdout, environ)
        message = str(item.get("message", "")).strip()
        source = str(item.get("source", "")).strip()
        line = str(item.get("line", "")).strip()
        location = f"{source}:{line}" if source and line else source
        remediation = str(item.get("suggested_remediation", "")).strip()
        if str(item.get("rule", "")).startswith("secrets.") and "value" in message.lower():
            print(f"{severity_label} {message}", file=stdout)
            if location:
                print(location, file=stdout)
            print(remediation or "Value redacted.", file=stdout)
            continue
        if message:
            print(f"{severity_label} {message}", file=stdout)
            if location:
                print(location, file=stdout)
            if remediation:
                print(remediation, file=stdout)
    remaining = len(items) - 3
    if remaining > 0:
        print(f"  - {remaining} more policy item(s)", file=stdout)


def _color(text: str, color: str, stdout: TextIO, environ: Mapping[str, str]) -> str:
    if not _supports_color(stdout, environ):
        return text
    code = {"green": "32", "yellow": "33", "red": "31", "bold_red": "1;31"}[color]
    return f"\033[{code}m{text}\033[0m"


def _supports_color(stdout: TextIO, environ: Mapping[str, str]) -> bool:
    return "NO_COLOR" not in environ and hasattr(stdout, "isatty") and stdout.isatty()


def _format_severity(
    severity: str,
    stdout: TextIO,
    environ: Mapping[str, str],
) -> str:
    label = severity.upper()
    color = {
        "CRITICAL": "red",
        "HIGH": "bold_red",
        "MEDIUM": "yellow",
    }.get(label)
    if color is None:
        return label
    return _color(label, color, stdout, environ)


def _shell_double_quote(value: str) -> str:
    return f'"{_shell_double_quote_content(value)}"'


def _shell_double_quote_content(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
