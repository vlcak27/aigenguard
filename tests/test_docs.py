from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_troubleshooting_doc_exists_and_covers_common_issues():
    path = ROOT / "docs" / "troubleshooting.md"

    assert path.exists()
    text = path.read_text(encoding="utf-8")

    assert "aigenguard: command not found" in text
    assert "Windows 11 / PowerShell activation" in text
    assert "--open does not open the browser" in text
    assert "--enforce-policy" in text
    assert "Pre-commit hook cannot find aigenguard" in text
    assert "Bypass local hook" in text
    assert "Secret values are not shown" in text


def test_readme_links_to_troubleshooting_doc():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "[Troubleshooting](docs/troubleshooting.md)" in text


def test_precision_doc_exists_and_explains_static_scope():
    text = (ROOT / "docs" / "precision.md").read_text(encoding="utf-8")

    assert "static precision regression corpus" in text
    assert "good cases" in text
    assert "bad cases" in text
    assert "false-positive" in text
    assert "policy-documented" in text
    assert "not comprehensive vulnerability coverage" in text
    assert "not exploit proof" in text
    assert "does not execute scanned code" in text
    assert "does not execute MCP servers" in text
    assert "does not make network calls" in text
    assert "Confidence means the strength of static evidence, not exploitability" in text


def test_confidence_docs_define_static_evidence_model():
    precision = (ROOT / "docs" / "precision.md").read_text(encoding="utf-8")
    report_guide = (ROOT / "docs" / "report-guide.md").read_text(encoding="utf-8")
    taxonomy = (ROOT / "docs" / "agent-risk-taxonomy.md").read_text(encoding="utf-8")
    combined = "\n".join([precision, report_guide, taxonomy]).lower()

    assert "strength of static evidence" in combined
    assert "not exploitability" in combined
    assert "severity and confidence are different" in combined
    assert "high confidence" in combined
    assert "medium confidence" in combined
    assert "low confidence" in combined
    assert "parsed executable code evidence" in combined
    assert "structured config evidence" in combined
    assert "text-only evidence" in combined
    assert "policy can document risk without proving safety" in combined
    assert "agent capability" in combined
    assert "pre-commit review" in combined
    assert "capability-diff" in combined


def test_rename_docs_explain_agentbom_backward_compatibility():
    paths = [
        ROOT / "README.md",
        ROOT / "docs" / "policy.md",
        ROOT / "docs" / "report-guide.md",
        ROOT / "ROADMAP.md",
        ROOT / "CHANGELOG.md",
    ]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "AgentBOM is now AigenGuard." in text
        assert "`agentbom` CLI and `agentbom.toml` remain supported during migration." in text
        assert "New projects should use `aigenguard` and `aigenguard.toml`." in text


def test_github_action_installs_checked_out_action_code():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")

    assert 'python -m pip install "$GITHUB_ACTION_PATH"' in text
    assert "pip install ai-agentbom" not in text
    assert "aigenguard scan" in text


def test_github_action_docs_prefer_new_repo_and_explain_old_action_compatibility():
    text = (ROOT / "docs" / "github-action.md").read_text(encoding="utf-8")

    assert "uses: vlcak27/aigenguard@v0.8.3" in text
    assert "`vlcak27/agentbom@...`" in text
    assert "do not rely on repository redirects alone" in text


def test_readme_includes_recommended_workflow_and_local_guard_example():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Recommended Workflow" in readme
    assert "aigenguard activate" in readme
    assert "git commit" in readme
    assert "creates or reuses `aigenguard.toml`" in readme
    assert "repo-local" in readme
    assert "default mode is `confirm`" in readme
    assert "AigenGuard OK" in readme
    assert "aigenguard scan . --policy aigenguard.toml --html --open" in readme
    assert "advisory" in readme
    assert "confirm" in readme
    assert "enforce" in readme
    assert "aigenguard deactivate" in readme


def test_policy_docs_explain_local_guard_modes_and_bypass():
    policy_docs = (ROOT / "docs" / "policy.md").read_text(encoding="utf-8")

    assert "## Activate AigenGuard in a Repository" in policy_docs
    assert "aigenguard activate" in policy_docs
    assert "aigenguard status" in policy_docs
    assert "global Git" in policy_docs
    assert "config" in policy_docs
    assert "aigenguard deactivate" in policy_docs
    assert "## Local Guard" in policy_docs
    assert "aigenguard guard . --policy aigenguard.toml --mode advisory" in policy_docs
    assert "aigenguard guard . --policy aigenguard.toml --mode confirm" in policy_docs
    assert "aigenguard guard . --policy aigenguard.toml --mode enforce" in policy_docs
    assert "AigenGuard OK" in policy_docs
    assert "AIGENGUARD_SKIP_HOOK=1 git commit" in policy_docs
    assert "`AGENTBOM_SKIP_HOOK=1` remains accepted as a compatibility alias." in policy_docs
    assert "git commit --no-verify" in policy_docs


def test_troubleshooting_docs_explain_confirm_and_aigenguard_command():
    troubleshooting = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")

    assert "Activate Says This Is Not a Git Repository" in troubleshooting
    assert "Existing Hook Prevents Activation" in troubleshooting
    assert "Status Says Hook Not Installed" in troubleshooting
    assert "aigenguard activate --append" in troubleshooting
    assert "aigenguard status" in troubleshooting
    assert "confirm mode requires an interactive terminal" in troubleshooting
    assert "--aigenguard-command .venv/bin/aigenguard" in troubleshooting
    assert "`--agentbom-command` option remains as an alias" in troubleshooting
    assert "aigenguard deactivate" in troubleshooting
