#!/usr/bin/env python3
"""Offline, pre-labelled real-Git review evaluation and optional timing."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from aigenguard.review import (markdown_review, review_exit_code, review_findings,
                               review_repository, terminal_review, write_review)
from aigenguard.scanner import scan_path
from aigenguard.diff import diff_reports
from aigenguard.report import render_markdown
from aigenguard.html_report import render_html
from aigenguard.mermaid import render_mermaid
from aigenguard.sarif import render_sarif
from aigenguard.cyclonedx import render_cyclonedx
from aigenguard.github_summary import render_github_step_summary


ROOT = Path(__file__).resolve().parents[1]
MCP_POLICY = '[mcp]\nwarn_on_unknown_server=false\nrequire_policy_for_risky_servers=false\n'
DEFAULT_POLICY = MCP_POLICY + '[secrets]\nwarn_on_detected=false\n'


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.check_output(["git", "-C", str(repo), *args], env=env, text=True,
                                   stderr=subprocess.PIPE).strip()


def initialize(repo):
    repo.mkdir()
    git(repo, "init", "-q")
    for name, value in (("user.name", "Offline Review Eval"), ("user.email", "eval@example.invalid"),
                        ("commit.gpgSign", "false")):
        git(repo, "config", name, value)


def put(repo, name, data):
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data, encoding="utf-8")


def validators():
    schemas = [json.loads((ROOT / "docs" / name).read_text())
               for name in ("review-schema.json", "output-schema.json")]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    return [Draft202012Validator(schema, registry=registry) for schema in schemas]


def check_outputs(report, bom, canaries, review_validator, scan_validator):
    review_validator.validate(report)
    scan_validator.validate(bom)
    markdown = markdown_review(report)
    findings = review_findings(report)
    assert markdown.count("- **") == len(findings), "Markdown/JSON finding count differs"
    for item in findings:
        assert f"{item['rule_id']} — {item['change']}" in markdown
    assert len({item["id"] for item in findings}) == len(findings), "duplicate occurrence ID"
    exports = [json.dumps(report), terminal_review(report), markdown, json.dumps(bom),
               render_markdown(bom), render_html(bom), render_mermaid(bom),
               json.dumps(render_sarif(bom)), json.dumps(render_cyclonedx(bom)),
               render_github_step_summary(bom, [])]
    assert all(token.lower() not in output.lower() for token in canaries for output in exports), "canary leaked"


def run_case(case, repo, checks):
    initialize(repo)
    name = case.get("file", ".mcp.json")
    def config_text(data, pretty=False):
        return data if isinstance(data, str) else json.dumps(data, sort_keys=pretty, indent=4 if pretty else None)
    put(repo, name, config_text(case["before"]))
    def fixture_policy(value):
        # Isolate labelled changes from unrelated default risky-server findings.
        return value if "[mcp]" in value else value + MCP_POLICY
    put(repo, "aigenguard.toml", fixture_policy(case.get("base_policy", DEFAULT_POLICY)))
    for path, data in case.get("base_files", {}).items():
        put(repo, path, data)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    before = scan_path(repo)
    put(repo, name, config_text(case["after"], case.get("format", False)))
    policy = case.get("head_policy", case.get("base_policy", DEFAULT_POLICY))
    if policy is None:
        (repo / "aigenguard.toml").unlink()
    else:
        put(repo, "aigenguard.toml", fixture_policy(policy))
    for path, data in case.get("files", {}).items():
        put(repo, path, data)
    special = case.get("special")
    if special == "oversized":
        put(repo, "unrelated.log", "x" * (1024 * 1024 + 1))
    elif special == "symlink":
        (repo / "unrelated-link").symlink_to("missing-target")
    elif special == "excluded":
        put(repo, "node_modules/agent.py", 'model="gpt-4"\n')
    elif special == "excluded-config":
        put(repo, "node_modules/.mcp.json", config_text(case["after"]))
    git(repo, "add", "--all")
    bom = scan_path(repo)
    bom["diff"] = diff_reports(before, bom)
    if "worktree" in case:
        put(repo, name, config_text(case["worktree"]))
    start = time.perf_counter()
    report = review_repository(repo, base="HEAD", staged=True)
    elapsed = time.perf_counter() - start
    repeat = review_repository(repo, base="HEAD", staged=True)
    assert report == repeat, "non-deterministic review"
    actual = sorted(item["rule_id"] + ":" + item["change"]
                    for item in report["mcp_changes"] + report["policy_changes"])
    baseline = sorted(item["rule_id"] for item in report["baseline_policy"]["violations"])
    code = review_exit_code(report, "medium")
    check_outputs(report, bom, case.get("canaries", []), *checks)
    passed = (actual == sorted(case["expected"]) and baseline == sorted(case.get("baseline", []))
              and report["status"] == case["status"] and code == case["exit"])
    return {"scenario": case["id"], "group": case["group"], "origin": case["origin"],
            "expected": case["expected"], "actual": actual, "baseline_expected": case.get("baseline", []),
            "baseline_actual": baseline, "expected_status": case["status"], "status": report["status"],
            "expected_exit": case["exit"], "exit": code, "result": "PASS" if passed else "FAIL",
            "coverage": case["coverage"], "limitation": case["limitation"], "seconds": elapsed}, report


def benchmark(parent):
    rows = []
    for count in (20, 1000):
        repo = parent / f"benchmark-{count}"
        initialize(repo)
        put(repo, "aigenguard.toml", DEFAULT_POLICY)
        put(repo, ".mcp.json", '{"mcpServers":{"files":{"command":"mcp-server-filesystem","args":["/data"]}}}')
        for index in range(count):
            put(repo, f"source/file-{index:04}.py", "# synthetic inert source\n" + "# " + "x" * 1000 + "\n")
        files = [path for path in repo.rglob("*") if path.is_file() and ".git" not in path.parts]
        size = sum(path.stat().st_size for path in files)
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "benchmark base")
        samples = []
        for _ in range(3):
            start = time.perf_counter()
            report = review_repository(repo, base="HEAD", staged=True)
            samples.append(time.perf_counter() - start)
            assert report["status"] == "complete" and not report["mcp_changes"]
        rows.append({"files": len(files), "bytes": size, "seconds": samples,
                     "median_seconds": statistics.median(samples)})
    return {"python": platform.python_version(), "platform": platform.platform(),
            "machine": platform.machine(), "git": git(parent, "--version"),
            "method": "perf_counter wall time; full HEAD-versus-index review, 3 runs, no forced OS-cache flush; setup excluded",
            "repositories": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new output directory")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    cases = json.loads((ROOT / "tests/fixtures/review_corpus.json").read_text())["cases"]
    checks = validators()
    rows = []
    with tempfile.TemporaryDirectory(prefix="aigenguard-eval-") as scratch:
        parent = Path(scratch)
        for case in cases:
            row, report = run_case(case, parent / case["id"], checks)
            rows.append(row)
            write_review(report, args.output_dir / case["id"])
            print(f"{row['scenario']}: {row['result']} exit={row['exit']} status={row['status']}")
        if args.benchmark:
            (args.output_dir / "benchmark.json").write_text(json.dumps(benchmark(parent), indent=2) + "\n")
    (args.output_dir / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = ["| Scenario | Origin | Expected | Actual | Exit expected/actual | Coverage | Limitation |",
             "|---|---|---|---|---|---|---|"]
    for row in rows:
        expected = ", ".join(row["expected"] + row["baseline_expected"]) or "no changes"
        actual = ", ".join(row["actual"] + row["baseline_actual"]) or "no changes"
        lines.append(f"| {row['scenario']} | {row['origin']} | {expected}; {row['expected_status']} | {row['result']}: {actual}; {row['status']} | {row['expected_exit']}/{row['exit']} | {row['coverage']} | {row['limitation']} |")
    (args.output_dir / "results.md").write_text("\n".join(lines) + "\n")
    counts = Counter(row["group"] for row in rows)
    for group, total in sorted(counts.items()):
        passed = sum(row["result"] == "PASS" for row in rows if row["group"] == group)
        print(f"{group}: {passed}/{total} labelled cases passed (not population precision/recall)")
    return 0 if all(row["result"] == "PASS" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
