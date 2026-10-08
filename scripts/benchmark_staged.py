"""Offline benchmark: 500 inert Python files, staged scan and actual guarded commits."""

import os
import json
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from aigenguard.git_index import staged_snapshot
from aigenguard.scanner import scan_path

os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)

    def run(*args):
        return subprocess.run(
            args, cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    run("git", "init", "-q")
    run("git", "config", "user.email", "fixture@example.invalid")
    run("git", "config", "user.name", "Fixture")
    (root / "aigenguard.toml").write_text("[secrets]\nwarn_on_detected=false\n")
    for i in range(500):
        (root / f"file_{i}.py").write_text(f"# offline fixture {i}\nx = {i}\n")
    run("git", "add", ".")
    run(
        sys.executable,
        "-m",
        "aigenguard.cli",
        "install-hook",
        "--mode",
        "enforce",
        "--aigenguard-command",
        str(Path(sys.executable).parent / "aigenguard"),
    )
    rows = []
    for i in range(3):
        start = time.perf_counter()
        with staged_snapshot(root, "aigenguard.toml") as (snapshot, policy, _):
            scan_path(snapshot)
        scan = time.perf_counter() - start
        start = time.perf_counter()
        run("git", "commit", "--allow-empty", "-qm", f"fixture {i}")
        commit = time.perf_counter() - start
        rows.append(
            {"staged_scan_seconds": round(scan, 4), "guarded_commit_seconds": round(commit, 4)}
        )
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "files": 501,
                "bytes": sum(p.stat().st_size for p in root.iterdir() if p.is_file()),
                "runs": rows,
            },
            indent=2,
        )
    )
