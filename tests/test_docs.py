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
