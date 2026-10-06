#!/usr/bin/env python3
"""Reproduce the automated public-snapshot pilot using only an isolated local wheel.

No network, checkout, upstream imports, dependency installation or server execution.
Repositories must already contain the pinned objects in review-pilot.json.
Synthetic policy/URL overlays are new local Git objects, not upstream changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import venv


ROOT = Path(__file__).resolve().parents[1]
POLICY = b"# SYNTHETIC PILOT POLICY: scanner defaults only; not upstream approval.\n"


def git(repo, *args, data=None, index=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
               GIT_AUTHOR_NAME="Automated Pilot", GIT_COMMITTER_NAME="Automated Pilot",
               GIT_AUTHOR_EMAIL="pilot@example.invalid", GIT_COMMITTER_EMAIL="pilot@example.invalid",
               GIT_AUTHOR_DATE="2026-09-30T00:00:00Z", GIT_COMMITTER_DATE="2026-09-30T00:00:00Z")
    if index:
        env["GIT_INDEX_FILE"] = str(index)
    result = subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=" + os.devnull,
                             "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
                             "-c", "commit.gpgsign=false", *args], env=env, input=data,
                            capture_output=True)
    if result.returncode:
        raise RuntimeError("Local Git object operation failed; no automatic fetch attempted")
    return result.stdout


def overlay(repo, original, changes, index):
    git(repo, "read-tree", original, index=index)
    for path, value in changes.items():
        oid = git(repo, "hash-object", "-w", "--stdin", data=value).decode().strip()
        git(repo, "update-index", "--add", "--cacheinfo", "100644", oid, path, index=index)
    tree = git(repo, "write-tree", index=index).decode().strip()
    return git(repo, "commit-tree", tree, "-p", original,
               data=b"SYNTHETIC local pilot overlay; not an upstream commit\n").decode().strip()


def labels(report):
    return sorted(item["file"] + ":" + item["rule_id"] + ":" + item["change"]
                  for item in report["mcp_changes"] + report["policy_changes"])


def run(args):
    manifest = json.loads((ROOT / "tests/fixtures/review-pilot.json").read_text())
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    wheel = args.wheel.resolve()
    rows = []
    with tempfile.TemporaryDirectory(prefix="aigenguard-public-pilot-") as directory:
        scratch = Path(directory).resolve()
        environment = scratch / "clean-wheel"
        venv.EnvBuilder(with_pip=True).create(environment)
        bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        scanner = bin_dir / ("aigenguard.exe" if os.name == "nt" else "aigenguard")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("GIT_", "PYTHON", "PIP_"))}
        env.update(PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                       cwd=scratch, env=env, check=True, capture_output=True)
        subprocess.run([str(python), "-I", "-c", "import aigenguard,pathlib,sys; "
                        "assert pathlib.Path(aigenguard.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve())"],
                       cwd=scratch, env=env, check=True)
        version = subprocess.check_output([str(scanner), "--version"], cwd=scratch, env=env, text=True).strip()
        receipt = {"wheel": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                   "tool": version, "python": platform.python_version(), "platform": platform.platform(),
                   "installation": "new venv; local wheel --no-index --no-deps; import path asserted inside venv",
                   "execution": "scanner only, from a trusted temporary cwd; no upstream code or checkout"}
        (output / "installation.json").write_text(json.dumps(receipt, indent=2) + "\n")
        for case in manifest["repositories"]:
            repo = (args.repos / case["id"]).resolve()
            original_base, original_head = case["base"], case["head"]
            policy_name = "aigenguard.toml"
            for ref in (original_base, original_head):
                names = git(repo, "ls-tree", "--name-only", ref).decode().splitlines()
                if "aigenguard.toml" in names or "agentbom.toml" in names:
                    raise RuntimeError("Upstream policy exists; manually review before overlaying it")
            index = scratch / (case["id"] + "-index")
            base = overlay(repo, original_base, {policy_name: POLICY}, index)
            head = overlay(repo, original_head, {policy_name: POLICY}, index)
            blob = original_head + ":" + case["file"]
            if int(git(repo, "cat-file", "-s", blob)) > 1024 * 1024:
                raise RuntimeError("Pilot config exceeds the read limit")
            data = json.loads(git(repo, "cat-file", "blob", blob))
            owner = data
            for key in case["pointer"][:-1]:
                owner = owner[key]
            owner[case["pointer"][-1]] = "https://pilot-destination.example.invalid/mcp"
            changed = overlay(repo, original_head, {policy_name: POLICY,
                              case["file"]: (json.dumps(data, indent=2) + "\n").encode()}, index)
            scenarios = [
                ("historical-native", original_base, original_head, case["historical_expected"], "incomplete", 2),
                ("historical-synthetic-policy", base, head, case["historical_expected"], case["overlay_status"], case["overlay_exit"]),
                ("synthetic-endpoint", head, changed, case["synthetic_expected"], case["overlay_status"], case["overlay_exit"]),
            ]
            for name, before, after, expected, status, code in scenarios:
                destination = output / case["id"] / name
                command = [str(scanner), "review", "--path", str(repo), "--base", before,
                           "--head", after, "--fail-on", "medium", "--output-dir", str(destination)]
                start = time.perf_counter()
                result = subprocess.run(command, cwd=scratch, env=env, capture_output=True, text=True)
                elapsed = time.perf_counter() - start
                report_path = destination / "aigenguard-review.json"
                if not report_path.exists():
                    raise RuntimeError("Installed scanner failed to produce a review report")
                report = json.loads(report_path.read_text())
                actual = labels(report)
                passed = actual == sorted(expected) and report["status"] == status and result.returncode == code
                row = {"repository": case["id"], "url": case["url"], "scenario": name,
                       "upstream_base": original_base, "upstream_head": original_head,
                       "review_base": before, "review_head": after, "synthetic_policy": name != "historical-native",
                       "expected": sorted(expected), "actual": actual,
                       "expected_status": status, "status": report["status"],
                       "expected_exit": code, "exit": result.returncode, "seconds": elapsed,
                       "coverage_issues": len(report["coverage"]["issues"]),
                       "baseline_violations": len(report["baseline_policy"]["violations"]),
                       "baseline_warnings": len(report["baseline_policy"]["warnings"]),
                       "result": "PASS" if passed else "MISMATCH", "interpretation": case["historical_reason"]
                       if name.startswith("historical") else "Controlled URL replacement; not an upstream vulnerability."}
                rows.append(row)
                # CLI has already redacted this output before its first write.
                (destination / "terminal.txt").write_text(result.stdout + result.stderr)
                print(f"{case['id']} {name}: {row['result']} {row['status']} exit={row['exit']} {elapsed:.3f}s")
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["| Repository | Scenario | Expected / actual changes | Status | Exit expected/actual | Seconds | Result |",
             "|---|---|---|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['repository']} | {row['scenario']} | {len(row['expected'])}/{len(row['actual'])} | {row['status']} | {row['expected_exit']}/{row['exit']} | {row['seconds']:.3f} | {row['result']} |")
    (output / "results.md").write_text("\n".join(lines) + "\n")
    return 0 if all(row["result"] == "PASS" for row in rows) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--repos", type=Path, required=True, help="local object repositories; no fetch performed")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory")
    raise SystemExit(run(parser.parse_args()))
