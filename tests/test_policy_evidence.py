import json

import pytest

from aigenguard.scanner import scan_path


@pytest.mark.parametrize("name", ["aigenguard.toml", "agentbom.toml", "custom.toml"])
@pytest.mark.parametrize("uses_model", [False, True])
def test_policy_rules_are_not_usage_evidence(tmp_path, name, uses_model):
    policy = tmp_path / name
    policy.write_text(
        '[models]\ndeny = ["gpt-4o"]\n'
        '[providers]\ndeny = ["openai"]\n'
        '[frameworks]\ndeny = ["langchain"]\n', encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        'from openai import OpenAI\nimport langchain\nmodel = "gpt-4o"\n'
        if uses_model else "print('safe')\n", encoding="utf-8",
    )
    result = scan_path(tmp_path, policy_path=policy if name == "custom.toml" else None)
    violations = result["policy_review"]["violations"]
    assert {item["rule"] for item in violations} == (
        {"models.deny", "providers.deny", "frameworks.deny"} if uses_model else set()
    )
    assert all(item["source"] == "agent.py" for item in violations)
    for category in ("models", "providers", "frameworks"):
        assert bool(result[category]) is uses_model


@pytest.mark.parametrize("name", ["aigenguard.toml", "agentbom.toml", "custom.toml"])
def test_policy_still_scans_secret_values(tmp_path, name):
    canary = "sk-proj-POLICYREGRESSION00000000000000000001"
    policy = tmp_path / name
    policy.write_text(
        f'[models]\ndeny = ["{canary}"]\n[secrets]\nblock_leaks = true\n',
        encoding="utf-8",
    )
    result = scan_path(tmp_path, policy_path=policy)
    assert result["secret_leak_findings"]
    assert any(item["rule"] == "secrets.block_leaks" for item in result["policy_review"]["violations"])
    assert canary not in json.dumps(result)
