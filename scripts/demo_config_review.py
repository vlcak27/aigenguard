#!/usr/bin/env python3
"""Offline, real-Git demo. Run after installing this checkout in a virtualenv."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run_demo(output: Path) -> list[dict]:
    scanner = shutil.which("aigenguard", path=str(Path(sys.executable).parent))
    if scanner is None:
        raise RuntimeError("Install this checkout into the Python environment running the demo first")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    repo = output / "repository"
    repo.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], env=env, text=True).strip()

    git("init", "-q")
    for key, value in (("user.name", "AigenGuard Demo"), ("user.email", "demo@example.invalid"),
                       ("commit.gpgSign", "false")):
        git("config", key, value)
    policy = '[mcp]\nallow_servers=["files"]\n[secrets]\nblock_leaks=true\n[models]\ndeny=["gpt-4o"]\n'

    def commit(label, path, rules=policy, agent="print('safe')\n", indent=None):
        config = {"mcpServers": {"files": {"command": "npx", "args": [
            "-y", "@modelcontextprotocol/server-filesystem", path,
        ]}}}
        (repo / ".mcp.json").write_text(json.dumps(config, indent=indent, sort_keys=bool(indent)))
        (repo / "aigenguard.toml").write_text(rules)
        (repo / "agent.py").write_text(agent)
        git("add", ".")
        git("commit", "-qm", label)
        return git("rev-parse", "HEAD")

    base = commit("base", "/workspace/project")
    a = commit("A formatting", "/workspace/project", indent=4)
    b = commit("B expanded filesystem", "/")
    c = commit("C expanded filesystem and weakened policy", "/", policy.replace('deny=["gpt-4o"]', "deny=[]"),
               'model="gpt-4o"\n')
    d = commit("D narrowed filesystem", "/workspace/project")
    rows = []
    scenarios = [("A", base, a, "no security change", 0),
                 ("B", a, b, "filesystem expanded", 1),
                 ("C", a, c, "filesystem expanded + policy weakened + original-policy violation", 1),
                 ("D", b, d, "filesystem narrowed", 0)]
    for name, before, after, expected, exit_code in scenarios:
        destination = output / name
        result = subprocess.run([scanner, "review", "--path", str(repo),
                                 "--base", before, "--head", after, "--fail-on", "high",
                                 "--output-dir", str(destination)], env=env, text=True, capture_output=True)
        if result.returncode != exit_code:
            raise RuntimeError(f"Scenario {name}: unexpected exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        report = json.loads((destination / "aigenguard-review.json").read_text())
        scope = [item["change"] for item in report["mcp_changes"] if item["rule_id"] == "mcp.filesystem_scope"]
        if name == "A":
            actual = "no security change" if not report["mcp_changes"] and not report["policy_changes"] else "unexpected changes"
        elif name == "C":
            weakened = any(item["change"] == "expanded" for item in report["policy_changes"])
            actual = ("filesystem expanded + policy weakened + original-policy violation"
                      if scope == ["expanded"] and weakened and report["baseline_policy"]["violations"] else "missing findings")
        else:
            actual = "filesystem " + (scope[0] if len(scope) == 1 else "unknown")
        if actual != expected or report["status"] != "complete":
            raise RuntimeError(f"Scenario {name}: semantic result differs from expectation")
        rows.append({"scenario": name, "expected": expected, "actual": actual, "exit": exit_code,
                     "base": before, "head": after})
        print(result.stdout)
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    table = ["| Scenario | Expected | Actual | Exit |", "|---|---|---|---|"]
    table.extend(f"| {row['scenario']} | {row['expected']} | {row['actual']} | {row['exit']} |" for row in rows)
    (output / "results.md").write_text("\n".join(table) + "\n")
    print("\n".join(table))
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path, help="new directory; existing data is not overwritten")
    run_demo(parser.parse_args().output_dir)
