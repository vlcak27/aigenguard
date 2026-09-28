"""Read a fixed Git index tree without checkout, filters, or symlink traversal."""

from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from .policy_paths import MAX_POLICY_FILE_SIZE


def git_output(root: Path, *args: str, environ: dict[str, str] | None = None) -> bytes:
    # An index refresh must not launch a repository-configured fsmonitor program.
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=environ,
    )
    if result.returncode:
        raise ValueError(f"Git {args[0]} failed; cannot verify repository/index state")
    return result.stdout


@contextmanager
def staged_snapshot(repo_root: Path, policy_path: str | Path):
    """Materialize regular blobs from one immutable tree, retaining relative paths."""
    policy = Path(policy_path)
    if not policy.is_absolute():
        policy = repo_root / policy
    # Do not resolve against working-tree symlinks: only the staged mode matters.
    try:
        policy_relative = Path(os.path.abspath(policy)).relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise ValueError("staged guard requires a policy inside the repository") from exc
    if policy.suffix.lower() != ".toml":
        raise ValueError("staged guard requires a TOML policy")

    git_dir = os.fsdecode(git_output(repo_root, "rev-parse", "--absolute-git-dir")).strip()
    index = os.fsdecode(git_output(
        repo_root, "rev-parse", "--path-format=absolute", "--git-path", "index",
    )).strip()
    with tempfile.TemporaryDirectory(prefix="aigenguard-index-") as directory:
        root = Path(directory)
        # write-tree can run clean filters when maintaining racy index stat data.
        # Give it an EMPTY worktree/cwd so no indexed path can be read. Keep the
        # original gitdir and effective index (including git commit --only's index).
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = index
        tree = git_output(
            root, f"--git-dir={git_dir}", f"--work-tree={directory}", "write-tree",
            environ=env,
        ).strip().decode("ascii")
        entries = git_output(repo_root, "ls-tree", "-r", "-z", "-l", "--full-tree", tree)
        policy_found = False
        destinations: dict[str, str] = {}
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, raw_name = entry.split(b"\t", 1)
            mode, kind, oid, size = metadata.split()
            name = os.fsdecode(raw_name)
            parts = PurePosixPath(name).parts
            if (
                not parts or "/".join(parts) != name
                or any(part in {".", "..", ".git"} for part in parts)
                or PurePosixPath(name).is_absolute()
                or (os.name == "nt" and any(
                    "\\" in part or ":" in part or part.endswith((".", " "))
                    or Path(part).is_reserved() for part in parts
                ))
            ):
                raise ValueError("index contains a path that cannot be safely scanned")
            is_policy = name == policy_relative
            # Neither symlinks nor submodules are materialized or followed.
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                if is_policy:
                    raise ValueError("staged policy must be a regular file, not a symlink")
                continue
            if int(size) > MAX_POLICY_FILE_SIZE:
                if is_policy:
                    raise ValueError("staged policy exceeds the 1 MB limit")
                continue
            for length in range(1, len(parts) + 1):
                prefix = "/".join(parts[:length])
                key = os.path.normcase(prefix)
                if key in destinations and destinations[key] != prefix:
                    raise ValueError("index paths collide on this filesystem")
                destinations[key] = prefix
            destination = root.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            # cat-file reads the raw blob. No smudge/clean filters or textconv.
            data = git_output(repo_root, "cat-file", "blob", oid.decode("ascii"))
            with destination.open("xb") as handle:
                handle.write(data)
            policy_found = policy_found or is_policy
        if not policy_found:
            raise ValueError("policy is missing from the index; stage it with git add")
        yield root, root.joinpath(*PurePosixPath(policy_relative).parts), policy_relative
