"""Real Git configuration-review regressions; all credentials are synthetic."""

import json
import os
import subprocess

import pytest

from aigenguard.cli import main
from aigenguard.review import review_repository, review_exit_code, markdown_review, terminal_review
from aigenguard.security_changes import configured_path, path_scope_change


PACKAGE = "@modelcontextprotocol/server-filesystem"
CANARY = "ghp_" + "SYNTHETICCANARY" * 3
POLICY = '[mcp]\nallow_servers = ["files"]\n[secrets]\nblock_leaks = true\n[models]\ndeny = ["gpt-4o"]\n'


def config(path="/workspace/project", *, name="files", **fields):
    return {"mcpServers": {name: {"command": "npx", "args": ["-y", PACKAGE, path], **fields}}}


def git(repo, *args, check=True, input=None):
    return subprocess.run(["git", "-C", str(repo), *args], text=True, input=input,
                          capture_output=True, check=check)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for key in os.environ:
        if key.startswith("GIT_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Review Test")
    git(root, "config", "user.email", "review@example.invalid")
    git(root, "config", "commit.gpgSign", "false")
    (root / ".mcp.json").write_text(json.dumps(config()))
    (root / "aigenguard.toml").write_text(POLICY)
    (root / "agent.py").write_text("print('safe')\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    return root


def stage(repo, data, file=".mcp.json"):
    (repo / file).write_text(json.dumps(data) if not isinstance(data, str) else data)
    git(repo, "add", "--", file)


def review(repo):
    return review_repository(repo, base="HEAD", staged=True)


def changes(report, rule):
    return [item for key in ("mcp_changes", "policy_changes") for item in report[key]
            if item["rule_id"] == rule]


def test_staged_scope_expansion_ignores_worktree_and_does_not_mutate_git(repo):
    stage(repo, config("/"))
    (repo / ".mcp.json").write_text(json.dumps(config()))
    before = {name: (repo / name).read_bytes() for name in (".git/index", ".git/config", ".mcp.json", ".git/HEAD")}
    report = review(repo)
    assert report["status"] == "complete"
    item, = changes(report, "mcp.filesystem_scope")
    assert item["change"] == "expanded" and item["severity"] == "high"
    assert item["before"] == ["posix:/workspace/project"]
    assert item["after"] == ["posix:/"]
    assert item["field"] == "/mcpServers/files/args"
    assert item["change_confidence"] == "high" and item["impact_confidence"] == "medium"
    assert review_exit_code(report, "high") == 1
    assert before == {name: (repo / name).read_bytes() for name in before}
    assert report == review(repo)
    assert markdown_review(report) == markdown_review(review(repo))


def test_formatting_key_order_and_filesystem_path_order_are_not_findings(repo):
    stage(repo, json.dumps(config(), indent=4, sort_keys=True))
    assert review(repo)["mcp_changes"] == []
    data = config()
    data["mcpServers"]["files"]["args"].append("/other")
    stage(repo, data)
    git(repo, "commit", "-qm", "two roots")
    data["mcpServers"]["files"]["args"][-2:] = ["/other", "/workspace/project"]
    stage(repo, data)
    assert review(repo)["mcp_changes"] == []


def test_renaming_server_preserves_visibility_as_removal_and_addition(repo):
    stage(repo, config("/", name="renamed"))
    report = review(repo)
    assert {item["change"] for item in changes(report, "mcp.server")} == {"added", "removed"}
    assert any("renamed" in item["component"] for item in report["mcp_changes"])


def test_original_policy_survives_candidate_weakening(repo):
    stage(repo, config("/"))
    stage(repo, POLICY.replace('deny = ["gpt-4o"]', 'deny = []'), "aigenguard.toml")
    stage(repo, 'model = "gpt-4o"\n', "agent.py")
    report = review(repo)
    assert changes(report, "mcp.filesystem_scope")[0]["change"] == "expanded"
    assert changes(report, "policy.models.deny")[0]["change"] == "expanded"
    assert report["baseline_policy"]["status"] == "evaluated"
    assert any(item["rule_id"] == "baseline.models.deny" for item in report["baseline_policy"]["violations"])


@pytest.mark.parametrize("before, after, kind", [
    ('[models]\nallow=["a"]', '[models]\nallow=[]', "expanded"),
    ('[models]\nallow=[]', '[models]\nallow=["a"]', "narrowed"),
    ('[models]\nallow=["a"]', '[models]\nallow=["b"]', "review_required"),
    ('[models]\nallow=["a"]\ndeny=["b"]', '[models]\nallow=["a"]\ndeny=[]', "no_effect"),
    ('[secrets]\nblock_leaks=true', '[secrets]\nblock_leaks=false', "expanded"),
    ('[mcp]\nrequire_policy_for_risky_servers=true', '[mcp]\nrequire_policy_for_risky_servers=false', "expanded"),
    ('[risk]\nwarn_on="high"', '[risk]\nwarn_on="critical"', "expanded"),
    ('[capabilities]\ndeny=["shell-execution"]', '[capabilities]\ndeny=["shell_execution"]', None),
    ('[mcp]\nwarn_on_unknown_server=true', '', None),
])
def test_policy_effective_semantics(repo, before, after, kind):
    stage(repo, before, "aigenguard.toml")
    git(repo, "commit", "-qm", "policy base")
    stage(repo, after, "aigenguard.toml")
    report = review(repo)
    if kind is None:
        assert report["policy_changes"] == []
    else:
        assert report["policy_changes"][0]["change"] == kind


@pytest.mark.parametrize("candidate, expected", [
    ('{ invalid JSON SYNTHETIC_PRIVATE_CANARY', "invalid"),
    ('{"unsupported": {}}', "unsupported"),
    ('{"mcpServers":{"files":{"command":[]}}}', "unsupported"),
    ('{"mcpServers":{"files":{"command":"x"},"files":{"command":"y"}}}', "ambiguous"),
])
def test_invalid_and_unsupported_mcp_is_incomplete(repo, candidate, expected):
    stage(repo, candidate)
    report = review(repo)
    assert report["status"] == "incomplete"
    assert review_exit_code(report) == review_exit_code(report, "critical") == 2
    assert expected in json.dumps(report["coverage"])
    assert "SYNTHETIC_PRIVATE_CANARY" not in json.dumps(report)


@pytest.mark.parametrize("candidate", [None, '[models]\nallow = "SYNTHETIC_PRIVATE_CANARY"'])
def test_missing_or_invalid_candidate_policy_retains_baseline_evaluation(repo, candidate):
    if candidate is None:
        git(repo, "rm", "aigenguard.toml")
    else:
        stage(repo, candidate, "aigenguard.toml")
    stage(repo, 'model = "gpt-4o"\n', "agent.py")
    report = review(repo)
    assert report["status"] == "incomplete"
    assert report["baseline_policy"]["violations"]
    assert changes(report, "policy.availability")[0]["change"] == "removed"
    assert "SYNTHETIC_PRIVATE_CANARY" not in json.dumps(report)


def test_missing_base_policy_is_never_success(repo):
    git(repo, "rm", "aigenguard.toml")
    git(repo, "commit", "-qm", "no base policy")
    stage(repo, POLICY, "aigenguard.toml")
    report = review(repo)
    assert review_exit_code(report) == 2
    assert report["baseline_policy"]["status"] == "not_evaluated"


def test_unknown_args_are_order_sensitive_and_always_omitted(repo, capsys, tmp_path):
    data = {"mcpServers": {"files": {"command": "custom", "args": ["a", "b"]}}}
    stage(repo, data)
    git(repo, "commit", "-qm", "custom base")
    canary = "SYNTHETIC_PRIVATE_CANARY_12345"
    data["mcpServers"]["files"]["args"] = [canary, "--token=" + canary]
    data["mcpServers"]["files"]["env"] = {"API_KEY": canary}
    data["mcpServers"]["files"]["url"] = f"https://user:{canary}@example.invalid/mcp?token={canary}#{canary}"
    stage(repo, data)
    output = tmp_path / "reports"
    assert main(["review", "--path", str(repo), "--base", "HEAD", "--staged", "--output-dir", str(output)]) == 0
    assert canary not in capsys.readouterr().out
    assert canary not in (output / "aigenguard-review.json").read_text()
    assert canary not in (output / "aigenguard-review.md").read_text()
    report = review(repo)
    assert changes(report, "mcp.arguments")[0]["change"] == "review_required"
    assert not changes(report, "mcp.filesystem_scope")
    assert changes(report, "mcp.environment")[0]["after"] == ["API_KEY"]
    assert changes(report, "mcp.endpoint")[0]["after"] == "https://example.invalid/[path/query omitted]"


def test_version_pin_to_floating_and_command_change(repo):
    data = config()
    data["mcpServers"]["files"]["args"][1] = PACKAGE + "@1.2.3"
    stage(repo, data)
    git(repo, "commit", "-qm", "pinned base")
    stage(repo, config())
    item, = changes(review(repo), "mcp.package_version")
    assert item["change"] == "expanded" and item["severity"] == "high"
    data["mcpServers"]["files"]["command"] = "uvx"
    stage(repo, data)
    assert changes(review(repo), "mcp.execution")[0]["change"] == "review_required"


@pytest.mark.parametrize("old, new, kind", [
    (["/workspace/project"], ["/"], "expanded"),
    (["/"], ["/workspace/project"], "narrowed"),
    (["/project"], ["/project2"], "review_required"),
    (["/project"], ["/project", "/project/sub"], "no_effect"),
    (["project"], ["."], "expanded"),
    (["project"], ["/"], "review_required"),
    (["C:\\project"], ["C:\\"], "expanded"),
    (["C:\\project"], ["D:\\"], "review_required"),
    (["C:\\project"], ["/"], "review_required"),
])
def test_path_components_and_platforms(old, new, kind):
    assert path_scope_change([configured_path(path) for path in old],
                             [configured_path(path) for path in new]) == kind


@pytest.mark.parametrize("path", ["${HOME}/project", "~/project", "%USERPROFILE%", "C:project", "../project"])
def test_paths_requiring_environment_are_not_expanded(path):
    assert configured_path(path) is None


def test_alternative_index_and_two_commits(repo, tmp_path, monkeypatch):
    baseline = git(repo, "rev-parse", "HEAD").stdout.strip()
    index = tmp_path / "other-index"
    monkeypatch.setenv("GIT_INDEX_FILE", str(index))
    git(repo, "read-tree", "HEAD")
    stage(repo, config("/"))
    original = index.read_bytes()
    assert changes(review(repo), "mcp.filesystem_scope")[0]["change"] == "expanded"
    assert index.read_bytes() == original
    git(repo, "commit", "-qm", "candidate")
    report = review_repository(repo, base=baseline, head="HEAD")
    assert report["snapshots"]["base"]["commit"] == baseline
    assert changes(report, "mcp.filesystem_scope")[0]["change"] == "expanded"


def test_review_never_executes_filters_fsmonitor_or_scanned_code(repo):
    stage(repo, 'from pathlib import Path\nPath("CODE_EXECUTED").touch()\n', "agent.py")
    stage(repo, "*.json filter=tripwire diff=tripwire\n", ".gitattributes")
    for option in ("filter.tripwire.clean", "filter.tripwire.smudge", "diff.tripwire.textconv", "diff.external", "core.fsmonitor"):
        git(repo, "config", option, "echo executed > GIT_PROGRAM_EXECUTED; cat")
    before = (repo / ".git/index").read_bytes()
    assert review(repo)["status"] == "complete"
    assert not (repo / "GIT_PROGRAM_EXECUTED").exists()
    assert not (repo / "CODE_EXECUTED").exists()
    assert (repo / ".git/index").read_bytes() == before


@pytest.mark.parametrize("file", [".mcp.json", "aigenguard.toml"])
@pytest.mark.parametrize("unsafe", ["oversized", "symlink", "binary"])
def test_unscannable_configuration_is_incomplete(repo, file, unsafe):
    if unsafe == "oversized":
        stage(repo, " " * 1_000_001, file)
    elif unsafe == "binary":
        stage(repo, "\0", file)
    else:
        oid = git(repo, "hash-object", "-w", "--stdin", input="/outside/private").stdout.strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},{file}")
    assert review_exit_code(review(repo)) == 2


@pytest.mark.parametrize("base", ["missing", "--help", "HEAD\nSYNTHETIC_PRIVATE_CANARY"])
def test_reference_errors_are_safe(repo, base):
    report = review_repository(repo, base=base, staged=True)
    assert report["status"] == "error" and review_exit_code(report) == 2
    assert "SYNTHETIC_PRIVATE_CANARY" not in terminal_review(report)


def test_initial_commit_without_head_is_explicit_error(tmp_path):
    git(tmp_path, "init", "-q")
    report = review_repository(tmp_path, base="HEAD", staged=True)
    assert "base commit is unavailable" in report["error"]
    assert review_exit_code(report) == 2


def test_named_array_reordering_keeps_identity_and_reports_real_field_pointer(repo):
    a = {"name": "files", "command": "npx", "args": ["-y", PACKAGE, "/workspace/project"]}
    b = {"name": "other", "command": "custom", "args": []}
    stage(repo, {"mcp": {"servers": [a, b]}})
    git(repo, "commit", "-qm", "array base")
    stage(repo, {"mcp": {"servers": [b, a]}})
    assert review(repo)["mcp_changes"] == []
    a["args"][-1] = "/"
    stage(repo, {"mcp": {"servers": [b, a]}})
    item, = changes(review(repo), "mcp.filesystem_scope")
    assert item["field"] == "/mcp/servers/1/args"
    assert item["component"].endswith("/mcp/servers/files")


def test_unknown_argument_order_is_not_normalized_away(repo):
    data = {"mcpServers": {"files": {"command": "custom", "args": ["read", "write"]}}}
    stage(repo, data)
    git(repo, "commit", "-qm", "argument base")
    data["mcpServers"]["files"]["args"].reverse()
    stage(repo, data)
    assert changes(review(repo), "mcp.arguments")[0]["change"] == "review_required"


def test_env_values_are_not_persisted_or_compared_and_env_key_order_is_irrelevant(repo):
    stage(repo, config(env={"A": "SYNTHETIC_ONE", "B": "SYNTHETIC_TWO"}))
    git(repo, "commit", "-qm", "env base")
    stage(repo, config(env={"B": "DIFFERENT_SYNTHETIC", "A": "ALSO_DIFFERENT"}))
    report = review(repo)
    assert not changes(report, "mcp.environment")
    assert "SYNTHETIC" not in json.dumps(report)
    assert "environment values" in report["coverage"]["not_evaluated"]


def test_mcp_removal_and_empty_container_are_complete(repo):
    stage(repo, {"mcpServers": {}})
    report = review(repo)
    assert report["status"] == "complete"
    assert changes(report, "mcp.server")[0]["change"] == "removed"


def test_unsupported_mcp_file_is_incomplete(repo):
    stage(repo, "servers: []\n", "mcp.yaml")
    assert review_exit_code(review(repo)) == 2


def test_cli_operational_failure_still_writes_safe_reports(repo, tmp_path, capsys):
    output = tmp_path / "failure-reports"
    result = main(["review", "--path", str(repo), "--base", "HEAD\nSYNTHETIC_PRIVATE_CANARY",
                   "--staged", "--output-dir", str(output)])
    assert result == 2
    for text in (capsys.readouterr().out, (output / "aigenguard-review.json").read_text(),
                 (output / "aigenguard-review.md").read_text()):
        assert "SYNTHETIC_PRIVATE_CANARY" not in text


def test_unknown_package_and_version_values_are_omitted(repo):
    data = config()
    data["mcpServers"]["files"]["args"] = ["-y", "synthetic-secret-canary@PRIVATE_CANARY"]
    stage(repo, data)
    text = json.dumps(review(repo))
    assert "synthetic-secret-canary" not in text and "PRIVATE_CANARY" not in text


def test_unchanged_server_in_same_file_is_still_unchanged(repo):
    from aigenguard.scanner import scan_path
    from aigenguard.diff import diff_reports

    data = config()
    data["mcpServers"]["other"] = {"command": "custom", "args": []}
    (repo / ".mcp.json").write_text(json.dumps(data))
    before = scan_path(repo)
    data["mcpServers"]["files"]["args"][-1] = "/"
    (repo / ".mcp.json").write_text(json.dumps(data))
    diff = diff_reports(before, scan_path(repo))
    assert any(item["title"] == "other" for item in diff["unchanged"])
    assert not any(item["title"] == "files" for item in diff["unchanged"])


def test_git_replace_does_not_change_base_contents(repo):
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    stage(repo, config("/"))
    git(repo, "commit", "-qm", "wide")
    wide = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "replace", base, wide)
    report = review_repository(repo, base=base, head=wide)
    assert changes(report, "mcp.filesystem_scope")[0]["change"] == "expanded"


def test_review_schema_required_fields(repo):
    stage(repo, config("/"))
    report = review(repo)
    assert report["schema_version"] == "1.1"
    for item in report["mcp_changes"]:
        assert {"id", "rule_id", "component", "file", "field", "change", "before", "after",
                "explanation", "recommendation", "severity", "change_confidence", "impact_confidence"} <= item.keys()


def test_invalid_environment_list_is_incomplete(repo):
    stage(repo, config(env=[42]))
    assert review_exit_code(review(repo)) == 2


def test_recognizable_credential_in_environment_name_never_leaks(repo):
    stage(repo, config(env={CANARY: "placeholder", "OPENAI_API_KEY": "placeholder"}))
    report = review(repo)
    for output in (json.dumps(report), terminal_review(report), markdown_review(report)):
        assert CANARY not in output
        assert "OPENAI_API_KEY" in output


def test_baseline_occurrences_have_unique_stable_useful_evidence(repo):
    stage(repo, '[models]\ndeny=["gpt-4o", "gpt-4"]\n', "aigenguard.toml")
    git(repo, "commit", "-qm", "two denials")
    stage(repo, 'model="gpt-4o"\n', "one.py")
    stage(repo, 'model="gpt-4"\nother_model="gpt-4o"\n', "two.py")
    report = review(repo)
    findings = [item for item in report["baseline_policy"]["violations"] if item["rule_id"] == "baseline.models.deny"]
    assert len(findings) == 3
    assert len({item["id"] for item in findings}) == 3
    assert findings == [item for item in review(repo)["baseline_policy"]["violations"] if item["rule_id"] == "baseline.models.deny"]
    assert all("gpt-4" in item["explanation"] for item in findings)


def test_filesystem_url_argument_is_opaque_and_redacted(repo):
    stage(repo, config("https://user:SYNTHETIC_PRIVATE_CANARY@example.invalid/?token=SYNTHETIC_QUERY_CANARY"))
    report = review(repo)
    assert changes(report, "mcp.arguments")[0]["change"] == "review_required"
    for output in (json.dumps(report), terminal_review(report), markdown_review(report)):
        assert "SYNTHETIC_" not in output


def test_offline_demo_runs_all_four_real_git_scenarios(tmp_path):
    from pathlib import Path
    import sys

    script = Path(__file__).resolve().parents[1] / "scripts/demo_config_review.py"
    output = tmp_path / "demo"
    subprocess.run([sys.executable, str(script), "--output-dir", str(output)],
                   check=True, capture_output=True, text=True)
    rows = json.loads((output / "results.json").read_text())
    assert [row["exit"] for row in rows] == [0, 1, 1, 0]
    assert all(row["expected"] == row["actual"] for row in rows)
