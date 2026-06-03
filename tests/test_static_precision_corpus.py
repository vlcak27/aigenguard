from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

import pytest


def load_precision_corpus_module() -> ModuleType:
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "precision_corpus.py"
    spec = importlib.util.spec_from_file_location("aigenguard_precision_corpus", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load precision corpus module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


precision_corpus = load_precision_corpus_module()


CASES = precision_corpus.load_cases()
GOOD_CASES = [case for case in CASES if case.get("kind") == "good"]
BAD_CASES = [case for case in CASES if case.get("kind") == "bad"]
EXPECTED_CASES = {
    "good/docs_only_mentions",
    "good/env_reference_only",
    "good/readme_example_only",
    "good/test_files_only",
    "good/config_names_only",
    "good/policy_documented_shell",
    "good/python_comments_only",
    "good/mcp_no_usable_servers",
    "good/env_example_names_only",
    "good/placeholder_credentials_text",
    "bad/leaked_ai_key_value",
    "bad/cross_output_secret_redaction",
    "bad/shell_exec_agent",
    "bad/code_exec_agent",
    "bad/mcp_filesystem_agent",
    "bad/unknown_mcp_server",
    "bad/prompt_allows_shell_agent",
    "bad/policy_gap_risky_capability",
}


def case_id(case: dict[str, Any]) -> str:
    return str(case["case"])


def scan_case(case: dict[str, Any]) -> dict[str, object]:
    return precision_corpus.scan_fixture(case)


def collect_findings(bom: dict[str, object], key: str) -> list[dict[str, object]]:
    return precision_corpus.list_items(bom, key)


def max_severity(bom: dict[str, object]) -> str:
    return precision_corpus.highest_severity(bom)


def assert_expected_signal_exists(bom: dict[str, object], signals: list[str]) -> None:
    assert precision_corpus.any_signal_exists(bom, signals), (
        "expected one of these signals: " + ", ".join(signals)
    )


def assert_no_unexpected_high_or_critical(
    case: dict[str, Any], bom: dict[str, object]
) -> None:
    allowed_sources = {
        str(source) for source in case.get("allowed_high_or_critical_sources", [])
    }
    unexpected = [
        (source, severity, item)
        for source, item, severity in precision_corpus.severity_items(bom)
        if source not in allowed_sources
        and precision_corpus.severity_rank(severity)
        >= precision_corpus.severity_rank("high")
    ]
    assert unexpected == []


def assert_no_high_or_critical_blocking_findings(bom: dict[str, object]) -> None:
    unexpected = [
        (source, severity, item)
        for source, item, severity in precision_corpus.severity_items(bom)
        if source in precision_corpus.BLOCKING_SOURCES
        and precision_corpus.severity_rank(severity)
        >= precision_corpus.severity_rank("high")
    ]
    assert unexpected == []


def assert_raw_values_absent(case: dict[str, Any], bom: dict[str, object]) -> None:
    failures = precision_corpus.raw_value_failures(case, bom)
    assert failures == []


def assert_expected_source_paths(case: dict[str, Any], bom: dict[str, object]) -> None:
    signals = [str(value) for value in case.get("expected_any", [])]
    for expected_path in case.get("expected_paths", []):
        assert precision_corpus.matching_source_path_exists(
            bom, signals, str(expected_path)
        ), f"expected signal source path {expected_path}"


def test_precision_manifest_lists_expected_cases_and_existing_fixtures():
    assert {case_id(case) for case in CASES} == EXPECTED_CASES
    for case in CASES:
        assert (precision_corpus.FIXTURE_ROOT / case_id(case)).is_dir()


@pytest.mark.parametrize("case", GOOD_CASES, ids=case_id)
def test_good_precision_cases_are_not_blocking(case: dict[str, Any]):
    bom = scan_case(case)

    assert_no_unexpected_high_or_critical(case, bom)
    assert_no_high_or_critical_blocking_findings(bom)
    assert collect_findings(bom, "secret_leak_findings") == []
    assert_raw_values_absent(case, bom)

    assert json.dumps(bom, sort_keys=True)


@pytest.mark.parametrize("case", GOOD_CASES, ids=case_id)
def test_good_precision_cases_have_false_positive_protections(case: dict[str, Any]):
    bom = scan_case(case)
    case_name = case_id(case)

    if case_name == "good/docs_only_mentions":
        assert not any(
            item.get("name") in {"shell", "code_execution", "mcp_tool_invocation"}
            for item in collect_findings(bom, "capabilities")
        )
        assert not any(
            item.get("capability") in {"shell", "code_execution", "mcp_tool_invocation"}
            for item in collect_findings(bom, "reachable_capabilities")
        )
        assert collect_findings(bom, "mcp_servers") == []

    if case_name in {
        "good/env_reference_only",
        "good/readme_example_only",
        "good/config_names_only",
        "good/env_example_names_only",
        "good/placeholder_credentials_text",
    }:
        assert collect_findings(bom, "secret_leak_findings") == []

    if case_name == "good/readme_example_only":
        assert "<OPENAI_API_KEY>" not in json.dumps(
            collect_findings(bom, "secret_leak_findings"),
            sort_keys=True,
        )

    if case_name == "good/policy_documented_shell":
        assert collect_findings(bom, "policy_findings") == []
        review = bom.get("policy_review")
        assert isinstance(review, dict)
        assert review["violations"] == []

    if case_name == "good/python_comments_only":
        assert not any(
            item.get("name") in {"shell", "code_execution"}
            for item in collect_findings(bom, "capabilities")
        )

    if case_name == "good/mcp_no_usable_servers":
        statuses = {
            str(item.get("parse_status"))
            for item in collect_findings(bom, "mcp_servers")
        }
        assert statuses == {"invalid_json", "no_servers"}
        assert all(
            item.get("risk") != "high"
            for item in collect_findings(bom, "mcp_servers")
        )


@pytest.mark.parametrize("case", BAD_CASES, ids=case_id)
def test_bad_precision_cases_detect_expected_risky_signals(case: dict[str, Any]):
    bom = scan_case(case)
    expected = [str(value) for value in case.get("expected_any", [])]

    assert_expected_signal_exists(bom, expected)
    assert_expected_source_paths(case, bom)
    assert_raw_values_absent(case, bom)
    assert precision_corpus.severity_rank(max_severity(bom)) >= precision_corpus.severity_rank(
        str(case["min_severity"])
    )


@pytest.mark.parametrize("case", BAD_CASES, ids=case_id)
def test_bad_precision_cases_have_precise_evidence(case: dict[str, Any]):
    bom = scan_case(case)
    case_name = case_id(case)

    if case_name == "bad/leaked_ai_key_value":
        leaks = collect_findings(bom, "secret_leak_findings")
        assert any(
            leak.get("provider") == "openai"
            and leak.get("path") == ".env"
            and leak.get("severity") == "critical"
            for leak in leaks
        )
        assert all("[REDACTED]" in str(leak.get("redacted_evidence", "")) for leak in leaks)

    if case_name == "bad/cross_output_secret_redaction":
        leaks = collect_findings(bom, "secret_leak_findings")
        leak_keys = {
            (
                leak.get("provider"),
                leak.get("category"),
                leak.get("path"),
                leak.get("line"),
            )
            for leak in leaks
        }
        assert ("openai", "api_key", ".env", 1) in leak_keys
        assert ("anthropic", "api_key", ".env", 2) in leak_keys
        assert ("github", "token", ".env", 3) in leak_keys
        assert all("[REDACTED]" in str(leak.get("redacted_evidence", "")) for leak in leaks)
        servers = collect_findings(bom, "mcp_servers")
        assert any(
            server.get("path") == "mcp.json"
            and server.get("name") == "sentinel-web"
            and server.get("args")
            == [
                "-y",
                "@modelcontextprotocol/server-fetch",
                "--api-key",
                "[redacted]",
                "--token=[redacted]",
                "https://example.invalid/sse",
            ]
            and server.get("env") == ["OPENAI_API_KEY", "SERVICE_TOKEN"]
            and "secrets_env_access" in server.get("risk_categories", [])
            for server in servers
        )

    if case_name == "bad/shell_exec_agent":
        assert {
            "name": "shell",
            "path": "agent.py",
            "confidence": "high",
        } in collect_findings(bom, "capabilities")

    if case_name == "bad/code_exec_agent":
        assert {
            "name": "code_execution",
            "path": "agent.py",
            "confidence": "high",
        } in collect_findings(bom, "capabilities")

    if case_name == "bad/mcp_filesystem_agent":
        servers = collect_findings(bom, "mcp_servers")
        assert any(
            "filesystem_access" in server.get("risk_categories", [])
            and server.get("path") == "mcp.json"
            for server in servers
        )

    if case_name == "bad/prompt_allows_shell_agent":
        assert {
            "name": "shell",
            "path": "AGENTS.md",
            "confidence": "low",
        } in collect_findings(bom, "capabilities")

    if case_name == "bad/policy_gap_risky_capability":
        assert any(
            finding.get("severity") == "high"
            and finding.get("source_file") == "agent.py"
            and "without restrictions" in str(finding.get("message", ""))
            for finding in collect_findings(bom, "policy_findings")
        )


def test_precision_corpus_harness_expectations_pass():
    results = [precision_corpus.evaluate_case(case) for case in CASES]

    failures = {
        result.case: result.failures
        for result in results
        if not result.passed
    }
    assert failures == {}
