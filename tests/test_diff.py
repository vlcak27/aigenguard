from __future__ import annotations

from aigenguard.diff import diff_reports, has_new_findings_at_or_above


def test_diff_reports_introduced_resolved_and_unchanged_findings():
    baseline = {
        "repository": "baseline",
        "providers": [{"name": "openai", "path": "agent.py", "confidence": "high"}],
        "capabilities": [{"name": "network", "path": "agent.py", "confidence": "high"}],
        "secret_references": [
            {"name": "OLD_API_KEY", "path": "agent.py", "confidence": "high"}
        ],
        "policy_findings": [
            {
                "severity": "low",
                "message": "prompt file detected without security policy",
                "source_file": "AGENTS.md",
            }
        ],
    }
    current = {
        "repository": "current",
        "providers": [{"name": "openai", "path": "agent.py", "confidence": "high"}],
        "capabilities": [
            {"name": "network", "path": "agent.py", "confidence": "high"},
            {"name": "shell", "path": "agent.py", "confidence": "high"},
        ],
        "secret_references": [
            {"name": "OPENAI_API_KEY", "path": "agent.py", "confidence": "high"}
        ],
        "policy_findings": [
            {
                "severity": "high",
                "message": "shell execution detected without restrictions",
                "source_file": "agent.py",
            }
        ],
    }

    diff = diff_reports(baseline, current)

    introduced = {(item["category"], item["title"], item["severity"]) for item in diff["introduced"]}
    resolved = {(item["category"], item["title"], item["severity"]) for item in diff["resolved"]}
    unchanged = {(item["category"], item["title"], item["severity"]) for item in diff["unchanged"]}

    assert ("capabilities", "shell", "high") in introduced
    assert ("secret_references", "OPENAI_API_KEY", "high") in introduced
    assert (
        "policy_findings",
        "shell execution detected without restrictions",
        "high",
    ) in introduced
    assert ("secret_references", "OLD_API_KEY", "high") in resolved
    assert (
        "policy_findings",
        "prompt file detected without security policy",
        "low",
    ) in resolved
    assert ("providers", "openai", "low") in unchanged
    assert ("capabilities", "network", "medium") in unchanged
    assert all(item["id"] for item in diff["introduced"])
    assert diff == diff_reports(baseline, current)


def test_fail_on_new_uses_severity_thresholds():
    diff = {
        "introduced": [
            {"severity": "low"},
            {"severity": "medium"},
        ]
    }

    assert has_new_findings_at_or_above(diff, "low") is True
    assert has_new_findings_at_or_above(diff, "medium") is True
    assert has_new_findings_at_or_above(diff, "high") is False
