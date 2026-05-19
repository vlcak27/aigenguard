"""Local git hook management for AgentBOM."""

from __future__ import annotations

import shlex
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path


MANAGED_BLOCK_START = "# >>> agentbom pre-commit guard >>>"
MANAGED_BLOCK_END = "# <<< agentbom pre-commit guard <<<"
MAX_HOOK_SIZE = 1_000_000


class HookError(ValueError):
    """Raised when a local git hook cannot be installed or removed safely."""


@dataclass(frozen=True)
class HookInstallResult:
    repo_root: Path
    hook_path: Path
    policy_path: str
    mode: str
    action: str


@dataclass(frozen=True)
class HookUninstallResult:
    repo_root: Path
    hook_path: Path
    action: str


def install_pre_commit_hook(
    path: str | Path,
    *,
    policy_path: str | Path = "agentbom.toml",
    enforce_policy: bool = False,
    append: bool = False,
    force: bool = False,
    agentbom_command: str = "agentbom",
) -> HookInstallResult:
    """Install or update the AgentBOM managed pre-commit hook block."""
    if not str(policy_path).strip():
        raise HookError("--policy must not be empty")
    if not agentbom_command.strip():
        raise HookError("--agentbom-command must not be empty")
    repo_root = find_git_root(path)
    hook_path = git_hook_path(repo_root)
    stored_policy_path = policy_path_for_hook(repo_root, policy_path)
    block = render_pre_commit_block(
        policy_path=stored_policy_path,
        enforce_policy=enforce_policy,
        agentbom_command=agentbom_command,
    )
    full_hook = "#!/bin/sh\n\n" + block

    hook_path.parent.mkdir(parents=True, exist_ok=True)
    action = "created"
    if hook_path.exists() or hook_path.is_symlink():
        if hook_path.is_symlink():
            if not force:
                raise HookError(
                    f"existing pre-commit hook is a symlink: {hook_path}. "
                    "Use --force to replace it."
                )
            hook_path.unlink()
            new_text = full_hook
            action = "overwritten"
        elif not hook_path.is_file():
            raise HookError(f"pre-commit hook is not a regular file: {hook_path}")
        elif force:
            try:
                existing_text = read_hook_text(hook_path)
            except HookError:
                existing_text = ""
            if has_complete_managed_block(existing_text):
                new_text = replace_managed_block(existing_text, block)
                action = "updated"
            else:
                new_text = full_hook
                action = "overwritten"
        else:
            existing_text = read_hook_text(hook_path)
            if has_complete_managed_block(existing_text):
                new_text = replace_managed_block(existing_text, block)
                action = "updated"
            elif has_partial_managed_block(existing_text):
                raise HookError(
                    f"existing pre-commit hook has an incomplete AgentBOM block: {hook_path}. "
                    "Use --force to replace it."
                )
            elif append:
                new_text = append_managed_block(existing_text, block)
                action = "appended"
            else:
                raise HookError(
                    f"existing pre-commit hook is not managed by AgentBOM: {hook_path}. "
                    "Use --append to add an AgentBOM managed block or --force to replace it."
                )
    else:
        new_text = full_hook

    hook_path.write_text(new_text, encoding="utf-8")
    make_executable(hook_path)
    return HookInstallResult(
        repo_root=repo_root,
        hook_path=hook_path,
        policy_path=stored_policy_path,
        mode="enforced" if enforce_policy else "advisory",
        action=action,
    )


def uninstall_pre_commit_hook(path: str | Path) -> HookUninstallResult:
    """Remove the AgentBOM managed block from a local pre-commit hook."""
    repo_root = find_git_root(path)
    hook_path = git_hook_path(repo_root)
    if not hook_path.exists() and not hook_path.is_symlink():
        return HookUninstallResult(repo_root=repo_root, hook_path=hook_path, action="missing")
    if hook_path.is_symlink():
        raise HookError(f"pre-commit hook is a symlink and was not modified: {hook_path}")
    if not hook_path.is_file():
        raise HookError(f"pre-commit hook is not a regular file: {hook_path}")

    existing_text = read_hook_text(hook_path)
    if has_partial_managed_block(existing_text) and not has_complete_managed_block(existing_text):
        raise HookError(f"pre-commit hook has an incomplete AgentBOM block: {hook_path}")
    if not has_complete_managed_block(existing_text):
        return HookUninstallResult(repo_root=repo_root, hook_path=hook_path, action="not-found")

    new_text = remove_managed_block(existing_text)
    if is_empty_hook(new_text):
        hook_path.unlink()
        return HookUninstallResult(repo_root=repo_root, hook_path=hook_path, action="removed-hook")

    hook_path.write_text(new_text, encoding="utf-8")
    make_executable(hook_path)
    return HookUninstallResult(repo_root=repo_root, hook_path=hook_path, action="removed-block")


def find_git_root(path: str | Path) -> Path:
    repo_path = Path(path)
    if not repo_path.exists():
        raise HookError(f"path does not exist: {repo_path}")
    if not repo_path.is_dir():
        raise HookError(f"path is not a directory: {repo_path}")
    output = run_git(repo_path, "rev-parse", "--show-toplevel", not_repo_message=repo_path)
    root = output.strip()
    if not root:
        raise HookError(f"could not determine git repository root from: {repo_path}")
    return Path(root).resolve()


def git_hook_path(repo_root: Path) -> Path:
    output = run_git(repo_root, "rev-parse", "--git-path", "hooks/pre-commit")
    hook_path = Path(output.strip())
    if not hook_path.is_absolute():
        hook_path = repo_root / hook_path
    return hook_path


def policy_path_for_hook(repo_root: Path, policy_path: str | Path) -> str:
    policy = Path(policy_path)
    if policy.is_absolute():
        absolute_policy = policy.resolve(strict=False)
    else:
        absolute_policy = (repo_root / policy).resolve(strict=False)
    try:
        return absolute_policy.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return absolute_policy.as_posix()


def render_pre_commit_block(
    *,
    policy_path: str,
    enforce_policy: bool,
    agentbom_command: str,
) -> str:
    quoted_policy = shlex.quote(policy_path)
    quoted_command = shlex.quote(agentbom_command)
    pretty_line = '    --pretty \\'
    enforce_lines = ["    --enforce-policy"] if enforce_policy else []
    if not enforce_policy:
        pretty_line = "    --pretty"
    scan_lines = [
        "  # shellcheck disable=SC2086",
        "  $AGENTBOM_COMMAND scan . \\",
        '    --policy "$AGENTBOM_POLICY_FILE" \\',
        '    --output-dir "$AGENTBOM_REPORT_DIR" \\',
        pretty_line,
        *enforce_lines,
    ]
    return "\n".join(
        [
            MANAGED_BLOCK_START,
            "# Managed by AgentBOM. Re-run `agentbom install-hook` to update.",
            "(",
            "  set -eu",
            "",
            '  if [ "${AGENTBOM_SKIP_HOOK:-}" = "1" ]; then',
            '    echo "Skipping AgentBOM policy guard (AGENTBOM_SKIP_HOOK=1)."',
            "    exit 0",
            "  fi",
            "",
            '  echo "Running AgentBOM policy guard..."',
            "",
            '  AGENTBOM_REPO_ROOT="$(git rev-parse --show-toplevel)"',
            '  cd "$AGENTBOM_REPO_ROOT"',
            "",
            f"  AGENTBOM_POLICY_FILE={quoted_policy}",
            f"  AGENTBOM_COMMAND={quoted_command}",
            "",
            '  if [ ! -f "$AGENTBOM_POLICY_FILE" ]; then',
            '    echo "AgentBOM policy file not found: $AGENTBOM_POLICY_FILE"',
            '    echo "Run: agentbom init"',
            "    exit 1",
            "  fi",
            "",
            '  AGENTBOM_REPORT_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t agentbom)"',
            '  trap \'rm -rf "$AGENTBOM_REPORT_DIR"\' EXIT',
            "",
            *scan_lines,
            ")",
            "AGENTBOM_HOOK_STATUS=$?",
            'if [ "$AGENTBOM_HOOK_STATUS" -ne 0 ]; then',
            '  exit "$AGENTBOM_HOOK_STATUS"',
            "fi",
            MANAGED_BLOCK_END,
            "",
        ]
    )


def read_hook_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise HookError(f"could not inspect pre-commit hook: {path}") from exc
    if size > MAX_HOOK_SIZE:
        raise HookError(f"pre-commit hook is larger than 1 MB and was not modified: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise HookError(f"pre-commit hook is not UTF-8 text and was not modified: {path}") from exc
    except OSError as exc:
        raise HookError(f"could not read pre-commit hook: {path}") from exc


def has_complete_managed_block(text: str) -> bool:
    return text.count(MANAGED_BLOCK_START) == 1 and text.count(MANAGED_BLOCK_END) == 1


def has_partial_managed_block(text: str) -> bool:
    return MANAGED_BLOCK_START in text or MANAGED_BLOCK_END in text


def replace_managed_block(text: str, block: str) -> str:
    start = text.index(MANAGED_BLOCK_START)
    end = text.index(MANAGED_BLOCK_END, start) + len(MANAGED_BLOCK_END)
    if end < len(text) and text[end : end + 1] == "\n":
        end += 1
    return text[:start] + block + text[end:]


def append_managed_block(text: str, block: str) -> str:
    separator = "" if text.endswith("\n") else "\n"
    return text + separator + "\n" + block


def remove_managed_block(text: str) -> str:
    start = text.index(MANAGED_BLOCK_START)
    end = text.index(MANAGED_BLOCK_END, start) + len(MANAGED_BLOCK_END)
    if end < len(text) and text[end : end + 1] == "\n":
        end += 1
    return text[:start] + text[end:]


def is_empty_hook(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and stripped != "#!/bin/sh":
            return False
    return True


def make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR)


def run_git(
    path: Path,
    *args: str,
    not_repo_message: Path | None = None,
) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise HookError("git is not available; install Git to manage local hooks") from exc
    if completed.returncode != 0:
        if not_repo_message is not None:
            raise HookError(f"not inside a git repository: {not_repo_message}")
        details = completed.stderr.strip() or completed.stdout.strip()
        message = f"git {' '.join(args)} failed"
        if details:
            message = f"{message}: {details}"
        raise HookError(message)
    return completed.stdout
