"""Read a fixed Git index tree without checkout, filters, or symlink traversal."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

from .policy_paths import MAX_POLICY_FILE_SIZE


def _git_invocation(root: Path, args, environ=None):
    # An index refresh must not launch a repository-configured fsmonitor program.
    env = dict(os.environ if environ is None else environ)
    env.update(GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1")
    return ["git", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-C", str(root), *args], env


def git_output(root: Path, *args: str, environ: dict[str, str] | None = None,
               input_data: bytes | None = None) -> bytes:
    command, env = _git_invocation(root, args, environ)
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env, input=input_data,
    )
    if result.returncode:
        raise ValueError(f"Git {args[0]} failed; cannot verify repository/index state")
    return result.stdout


@contextmanager
def raw_blob_reader(repo_root: Path):
    """One bounded raw-object stream; no filters, lazy fetch, or persistent cache."""
    command, env = _git_invocation(repo_root, ["cat-file", "--batch"])
    process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        def read(oid: bytes, expected_size: int) -> bytes:
            if not 0 <= expected_size <= MAX_POLICY_FILE_SIZE:
                raise ValueError("snapshot blob exceeds the read limit")
            process.stdin.write(oid + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(256).split()
            if header != [oid, b"blob", str(expected_size).encode("ascii")]:
                raise ValueError("snapshot blob unavailable or metadata changed")
            data = process.stdout.read(expected_size)
            if len(data) != expected_size or process.stdout.read(1) != b"\n":
                raise ValueError("snapshot blob unavailable or truncated")
            return data
        yield read
    finally:
        process.stdin.close()
        process.stdout.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


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


def resolve_commit(repo_root: Path, ref: str, label: str) -> str:
    if (not ref or ref.startswith("-") or len(ref) > 256
            or not re.fullmatch(r"[A-Za-z0-9_./~^@{}-]+", ref)):
        raise ValueError(f"invalid {label} reference; use a local commit SHA or Git revision")
    try:
        return git_output(repo_root, "rev-parse", "--verify", "--end-of-options",
                          ref + "^{commit}").decode("ascii").strip()
    except ValueError as exc:
        raise ValueError(f"{label} commit is unavailable locally; no automatic fetch was attempted") from exc


@contextmanager
def review_snapshot(repo_root: Path, *, ref: str | None, label: str):
    """Read one commit or the actual index without write-tree/index refresh.

    Index identity is a SHA-256 of the captured index entry manifest, not a Git
    tree OID. Captured blob OIDs are immutable, including for an alternate index.
    """
    if ref is not None:
        commit = resolve_commit(repo_root, ref, label)
        tree = git_output(repo_root, "rev-parse", commit + "^{tree}").decode("ascii").strip()
        listing = git_output(repo_root, "ls-tree", "-r", "-z", "--full-tree", tree)
        descriptor = {"kind": "commit", "commit": commit, "tree": tree}
    else:
        listing = git_output(repo_root, "ls-files", "--stage", "-z", "--cached")
        descriptor = {"kind": "index", "manifest_sha256": hashlib.sha256(listing).hexdigest()}
    entries = []
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        if ref is None:
            mode, oid, stage = metadata.split()
            if stage != b"0":
                raise ValueError("unmerged index; cannot verify a single candidate snapshot")
            kind = b"commit" if mode == b"160000" else b"blob"
        else:
            mode, kind, oid = metadata.split()
        entries.append((mode, kind, oid, os.fsdecode(name)))
    objects = sorted({oid for mode, kind, oid, name in entries if kind == b"blob"})
    sizes = {}
    if objects:
        checked = git_output(repo_root, "cat-file", "--batch-check", input_data=b"\n".join(objects) + b"\n")
        for line in checked.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[1] != b"blob" or not parts[2].isdigit():
                raise ValueError("snapshot blob unavailable locally; review is incomplete")
            sizes[parts[0]] = int(parts[2])
    with tempfile.TemporaryDirectory(prefix="aigenguard-review-") as directory, raw_blob_reader(repo_root) as read_blob:
        root = Path(directory)
        skipped, destinations = [], {}
        for mode, kind, oid, name in entries:
            parts = PurePosixPath(name).parts
            if (not parts or "/".join(parts) != name or PurePosixPath(name).is_absolute()
                    or any(part in {".", "..", ".git"} for part in parts)
                    or (os.name == "nt" and any(
                        "\\" in part or ":" in part or part.endswith((".", " "))
                        or Path(part).is_reserved() for part in parts))):
                raise ValueError("snapshot contains a path that cannot be safely materialized")
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                skipped.append({"file": name, "reason": "symlink or submodule"})
                continue
            if sizes[oid] > MAX_POLICY_FILE_SIZE:
                skipped.append({"file": name, "reason": "exceeds 1 MB"})
                continue
            for length in range(1, len(parts) + 1):
                prefix = "/".join(parts[:length])
                key = os.path.normcase(prefix)
                if key in destinations and destinations[key] != prefix:
                    raise ValueError("snapshot paths collide on this filesystem")
                destinations[key] = prefix
            destination = root.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = read_blob(oid, sizes[oid])
            if b"\0" in data:
                skipped.append({"file": name, "reason": "binary file"})
                continue
            with destination.open("xb") as handle:
                handle.write(data)
        yield root, descriptor, skipped
