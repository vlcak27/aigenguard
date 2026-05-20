from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_troubleshooting_doc_exists_and_covers_common_issues():
    path = ROOT / "docs" / "troubleshooting.md"

    assert path.exists()
    text = path.read_text(encoding="utf-8")

    assert "agentbom: command not found" in text
    assert "Windows 11 / PowerShell activation" in text
    assert "--open does not open the browser" in text
    assert "--enforce-policy" in text
    assert "Pre-commit hook cannot find agentbom" in text
    assert "Bypass local hook" in text
    assert "Secret values are not shown" in text


def test_readme_links_to_troubleshooting_doc():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "[Troubleshooting](docs/troubleshooting.md)" in text


def test_readme_includes_recommended_workflow_and_local_guard_example():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Recommended Workflow" in readme
    assert "agentbom activate" in readme
    assert "git commit" in readme
    assert "creates or reuses `agentbom.toml`" in readme
    assert "repo-local" in readme
    assert "default mode is `confirm`" in readme
    assert "AgentBOM OK" in readme
    assert "agentbom scan . --policy agentbom.toml --html --open" in readme
    assert "advisory" in readme
    assert "confirm" in readme
    assert "enforce" in readme
    assert "agentbom deactivate" in readme


def test_policy_docs_explain_local_guard_modes_and_bypass():
    policy_docs = (ROOT / "docs" / "policy.md").read_text(encoding="utf-8")

    assert "## Activate AgentBOM in a Repository" in policy_docs
    assert "agentbom activate" in policy_docs
    assert "agentbom status" in policy_docs
    assert "global Git" in policy_docs
    assert "config" in policy_docs
    assert "agentbom deactivate" in policy_docs
    assert "## Local Guard" in policy_docs
    assert "agentbom guard . --policy agentbom.toml --mode advisory" in policy_docs
    assert "agentbom guard . --policy agentbom.toml --mode confirm" in policy_docs
    assert "agentbom guard . --policy agentbom.toml --mode enforce" in policy_docs
    assert "AgentBOM OK" in policy_docs
    assert "AGENTBOM_SKIP_HOOK=1 git commit" in policy_docs
    assert "git commit --no-verify" in policy_docs


def test_troubleshooting_docs_explain_confirm_and_agentbom_command():
    troubleshooting = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")

    assert "Activate Says This Is Not a Git Repository" in troubleshooting
    assert "Existing Hook Prevents Activation" in troubleshooting
    assert "Status Says Hook Not Installed" in troubleshooting
    assert "agentbom activate --append" in troubleshooting
    assert "agentbom status" in troubleshooting
    assert "confirm mode requires an interactive terminal" in troubleshooting
    assert "--agentbom-command .venv/bin/agentbom" in troubleshooting
    assert "agentbom deactivate" in troubleshooting
