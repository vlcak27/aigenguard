"""Policy file discovery for AigenGuard and AgentBOM compatibility."""

from __future__ import annotations

from pathlib import Path


DEFAULT_POLICY_NAME = "aigenguard.toml"
LEGACY_POLICY_NAME = "agentbom.toml"
MAX_POLICY_FILE_SIZE = 1_000_000


def discover_policy_path(
    root: str | Path,
    explicit_path: str | Path | None = None,
    *,
    max_file_size: int | None = None,
) -> Path | None:
    """Resolve an explicit policy or discover the preferred repository policy."""
    if explicit_path is not None:
        return Path(explicit_path)
    root_path = Path(root)
    for name in (DEFAULT_POLICY_NAME, LEGACY_POLICY_NAME):
        candidate = root_path / name
        if _is_safe_discovered_policy(candidate, root_path, max_file_size=max_file_size):
            return candidate
    return None


def _is_safe_discovered_policy(
    candidate: Path,
    root: Path,
    *,
    max_file_size: int | None,
) -> bool:
    if candidate.is_symlink():
        return False
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
        stat = resolved_candidate.stat()
    except (FileNotFoundError, OSError, ValueError):
        return False
    if not resolved_candidate.is_file():
        return False
    return max_file_size is None or stat.st_size <= max_file_size


def preferred_policy_path(root: str | Path) -> Path:
    """Return the discovered policy or the preferred path for a new policy."""
    root_path = Path(root)
    for name in (DEFAULT_POLICY_NAME, LEGACY_POLICY_NAME):
        candidate = root_path / name
        if not _policy_candidate_exists(candidate):
            continue
        if _is_safe_discovered_policy(
            candidate,
            root_path,
            max_file_size=MAX_POLICY_FILE_SIZE,
        ):
            return candidate
        raise ValueError(f"unsafe repository policy file: {candidate}")
    return root_path / DEFAULT_POLICY_NAME


def _policy_candidate_exists(candidate: Path) -> bool:
    try:
        candidate.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True
