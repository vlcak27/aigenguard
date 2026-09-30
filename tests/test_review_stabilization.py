"""Display-boundary and identity regressions independent of the original demo."""

import json

import pytest

from aigenguard.diff import diff_reports
from aigenguard.scanner import scan_path
from aigenguard.review import markdown_review, review_repository, terminal_review, write_review
from test_review import CANARY, config, git, repo as repository_fixture, stage

repo = repository_fixture


OTHER = "ghp_" + "DIFFERENTCANARY" * 3


def exports(bom):
    from aigenguard.report import render_markdown
    from aigenguard.html_report import render_html
    from aigenguard.mermaid import render_mermaid
    from aigenguard.sarif import render_sarif
    from aigenguard.cyclonedx import render_cyclonedx
    from aigenguard.github_summary import render_github_step_summary
    return {
        "json": json.dumps(bom), "markdown": render_markdown(bom),
        "html": render_html(bom), "mermaid": render_mermaid(bom),
        "sarif": json.dumps(render_sarif(bom)), "cyclonedx": json.dumps(render_cyclonedx(bom)),
        "github_summary": render_github_step_summary(bom, []),
    }


@pytest.mark.parametrize("location", ["environment", "server", "file", "policy", "endpoint"])
def test_all_scan_exports_and_written_review_redact_identifiers(repo, tmp_path, location):
    data = config()
    file = ".mcp.json"
    if location == "environment":
        data["mcpServers"]["files"]["env"] = {CANARY: "placeholder", "OPENAI_API_KEY": "placeholder"}
    elif location == "server":
        data = config(name="prefix_" + CANARY)
    elif location == "file":
        (repo / CANARY).mkdir()
        file = CANARY + "/.mcp.json"
    elif location == "policy":
        stage(repo, '[mcp]\nallow_servers=["' + CANARY + '"]\n', "aigenguard.toml")
    else:
        data["mcpServers"]["files"]["url"] = f"https://user:{CANARY}@{CANARY}.invalid/path?token={CANARY}"
    stage(repo, data, file)
    bom = scan_path(repo)
    for name, output in exports(bom).items():
        assert CANARY.lower() not in output.lower(), name
    report = review_repository(repo, base="HEAD", staged=True)
    write_review(report, tmp_path / "reports")
    for output in [terminal_review(report), markdown_review(report),
                   *[path.read_text() for path in (tmp_path / "reports").iterdir()]]:
        assert CANARY.lower() not in output.lower()


@pytest.mark.parametrize("field", ["env", "server", "endpoint"])
def test_redacted_inputs_do_not_collapse_comparisons(repo, field):
    def data(token):
        return config(name=token) if field == "server" else config(**{
            "env" if field == "env" else "url": {token: "placeholder"} if field == "env"
            else "https://" + token + ".invalid/",
        })
    stage(repo, data(CANARY))
    git(repo, "commit", "-qm", "first sensitive identifier")
    before = scan_path(repo)
    stage(repo, data(OTHER))
    report = review_repository(repo, base="HEAD", staged=True)
    assert report["mcp_changes"]
    assert diff_reports(before, scan_path(repo))["security_changes"]
    assert CANARY not in json.dumps(report) and OTHER not in json.dumps(report)
    if field == "server":
        assert sorted(item["change"] for item in report["mcp_changes"]) == ["added", "removed"]
        from aigenguard.diff import has_new_findings_at_or_above
        assert has_new_findings_at_or_above(diff_reports(before, scan_path(repo)), "high")


def test_two_sensitive_servers_remain_distinct_in_one_container(repo):
    data = config(name=CANARY)
    data["mcpServers"].update(config(name=OTHER)["mcpServers"])
    stage(repo, data)
    git(repo, "commit", "-qm", "two servers")
    before = scan_path(repo)
    data["mcpServers"][OTHER]["args"][-1] = "/"
    stage(repo, data)
    events = diff_reports(before, scan_path(repo))["security_changes"]
    assert len(events) == 1 and events[0]["change"] == "expanded"


def test_repeated_secret_findings_keep_actual_lines(repo):
    stage(repo, 'key="' + CANARY + '"\nkey="' + CANARY + '"\n', "keys.py")
    report = review_repository(repo, base="HEAD", staged=True)
    items = [item for item in report["baseline_policy"]["violations"] if item["rule_id"] == "baseline.secrets.block_leaks"]
    assert {item["after"]["line"] for item in items} == {1, 2}
    assert len({item["id"] for item in items}) == 2
    assert CANARY not in json.dumps(items)


@pytest.mark.parametrize("small,large", [("/x/a", "/x"), ("C:/x/a", "C:/x"), ("work/a", "work")])
def test_comparable_scope_reversal_invariant(small, large):
    from aigenguard.security_changes import configured_path, path_scope_change
    a, b = [configured_path(small)], [configured_path(large)]
    assert path_scope_change(a, b) == "expanded"
    assert path_scope_change(b, a) == "narrowed"
    assert path_scope_change(a, a) == "no_effect"


def test_sensitive_policy_swap_is_visible_and_ids_stable(repo):
    stage(repo, '[mcp]\ndeny_servers=["' + CANARY + '"]\n', "aigenguard.toml")
    git(repo, "commit", "-qm", "sensitive denial")
    stage(repo, '[mcp]\ndeny_servers=["' + OTHER + '"]\n', "aigenguard.toml")
    report = review_repository(repo, base="HEAD", staged=True)
    item, = report["policy_changes"]
    assert item["change"] == "review_required"
    assert item["before"] == item["after"] == ["[REDACTED]"]
    assert report == review_repository(repo, base="HEAD", staged=True)


def test_older_security_metadata_remains_matchable(repo):
    before = scan_path(repo)
    for item in before["mcp_servers"]:
        item.get("security_config", {}).pop("identity_digest", None)
        item.get("security_config", {}).pop("env_identity", None)
    stage(repo, config("/"))
    events = diff_reports(before, scan_path(repo))["security_changes"]
    assert any(item["rule_id"] == "mcp.filesystem_scope" and item["change"] == "expanded" for item in events)
    assert not any(item["rule_id"] == "mcp.server" for item in events)


def test_scan_error_redacts_credential_in_unknown_policy_section(repo):
    stage(repo, '[' + CANARY + ']\nunknown=true\n', "aigenguard.toml")
    with pytest.raises(ValueError) as failure:
        scan_path(repo)
    assert CANARY not in str(failure.value)


def test_raw_blob_stream_checks_size_before_read_and_preserves_bytes(repo):
    from aigenguard.git_index import raw_blob_reader, MAX_POLICY_FILE_SIZE
    oid = git(repo, "rev-parse", "HEAD:.mcp.json").stdout.strip().encode()
    data = (repo / ".mcp.json").read_bytes()
    with raw_blob_reader(repo) as read:
        assert read(oid, len(data)) == data
        assert read(oid, len(data)) == data
        with pytest.raises(ValueError, match="read limit"):
            read(oid, MAX_POLICY_FILE_SIZE + 1)
        with pytest.raises(ValueError, match="metadata changed"):
            read(oid, len(data) - 1)
