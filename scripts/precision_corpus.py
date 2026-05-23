#!/usr/bin/env python3
"""Run the AgentBOM static precision fixture corpus."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "precision"
MANIFEST_PATH = FIXTURE_ROOT / "cases.json"
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_BY_RANK = {rank: severity for severity, rank in SEVERITY_RANK.items()}
BLOCKING_SOURCES = {"policy_findings", "policy_review.violations", "secret_leak_findings"}


@dataclass(frozen=True)
class CaseResult:
    case: str
    kind: str
    passed: bool
    highest: str
    expected_signal: str
    failures: list[str]


def load_cases(manifest_path: Path = MANIFEST_PATH) -> list[dict[str, Any]]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("precision cases manifest must be a JSON list")
    return [case for case in data if isinstance(case, dict)]


def scan_fixture(case: dict[str, Any], fixture_root: Path = FIXTURE_ROOT) -> dict[str, object]:
    from agentbom.scanner import scan_path

    fixture_path = fixture_root / str(case["case"])
    policy_name = case.get("policy")
    policy_path = fixture_path / str(policy_name) if isinstance(policy_name, str) else None
    return scan_path(fixture_path, policy_path=policy_path)


def evaluate_case(case: dict[str, Any], fixture_root: Path = FIXTURE_ROOT) -> CaseResult:
    failures: list[str] = []
    bom = scan_fixture(case, fixture_root)
    highest = highest_severity(bom)
    expected_signal = first_expected_signal(case)

    if case.get("kind") == "good":
        failures.extend(_evaluate_good_case(case, bom))
    elif case.get("kind") == "bad":
        failures.extend(_evaluate_bad_case(case, bom))
    else:
        failures.append("case kind must be good or bad")

    failures.extend(raw_value_failures(case, bom))
    return CaseResult(
        case=str(case.get("case", "")),
        kind=str(case.get("kind", "")),
        passed=not failures,
        highest=highest,
        expected_signal=expected_signal,
        failures=failures,
    )


def _evaluate_good_case(case: dict[str, Any], bom: dict[str, object]) -> list[str]:
    failures: list[str] = []
    allowed_sources = {
        str(source) for source in case.get("allowed_high_or_critical_sources", [])
    }
    for source, item, severity in severity_items(bom):
        if source in allowed_sources:
            continue
        if severity_rank(severity) >= severity_rank("high"):
            failures.append(f"unexpected {severity} finding in {source}: {short_item(item)}")

    for source, item, severity in severity_items(bom):
        if source not in BLOCKING_SOURCES:
            continue
        if severity_rank(severity) >= severity_rank("high"):
            failures.append(f"unexpected blocking {severity} finding: {short_item(item)}")

    if bom.get("secret_leak_findings"):
        failures.append("good case produced secret leak findings")

    case_name = str(case.get("case", ""))
    if case_name == "good/docs_only_mentions":
        failures.extend(_assert_no_capability_signals(bom, {"shell", "code_execution"}))
        if bom.get("mcp_servers"):
            failures.append("docs-only case produced MCP server findings")
        if any_signal_exists(bom, ["mcp_tool_invocation"]):
            failures.append("docs-only case produced MCP tool invocation evidence")
    if case_name in {
        "good/env_reference_only",
        "good/readme_example_only",
        "good/config_names_only",
        "good/test_files_only",
    } and bom.get("secret_leak_findings"):
        failures.append("name-only or placeholder secret reference became a leak")
    if case_name == "good/policy_documented_shell":
        if bom.get("policy_findings"):
            failures.append("documented shell case produced default policy findings")
        review = bom.get("policy_review")
        if isinstance(review, dict) and review.get("violations"):
            failures.append("documented shell case produced policy violations")
    return failures


def _evaluate_bad_case(case: dict[str, Any], bom: dict[str, object]) -> list[str]:
    failures: list[str] = []
    expected = [str(value) for value in case.get("expected_any", [])]
    if expected and not any_signal_exists(bom, expected):
        failures.append(f"missing expected signal, wanted one of: {', '.join(expected)}")

    min_severity = case.get("min_severity")
    if isinstance(min_severity, str) and severity_rank(highest_severity(bom)) < severity_rank(
        min_severity
    ):
        failures.append(f"highest severity {highest_severity(bom)} is below {min_severity}")

    expected_paths = [str(path) for path in case.get("expected_paths", [])]
    for expected_path in expected_paths:
        if not matching_source_path_exists(bom, expected, expected_path):
            failures.append(f"expected signal does not point to {expected_path}")

    case_name = str(case.get("case", ""))
    if case_name == "bad/mcp_filesystem_agent" and not any_signal_exists(
        bom, ["filesystem_access"]
    ):
        failures.append("MCP filesystem exposure was not detected")
    if case_name == "bad/policy_gap_risky_capability" and not any_signal_exists(
        bom, ["without restrictions", "without policy"]
    ):
        failures.append("policy gap was not detected")
    return failures


def _assert_no_capability_signals(
    bom: dict[str, object], names: set[str]
) -> list[str]:
    failures = []
    for item in list_items(bom, "capabilities"):
        if str(item.get("name")) in names:
            failures.append(f"unexpected capability evidence: {short_item(item)}")
    for item in list_items(bom, "reachable_capabilities"):
        if str(item.get("capability")) in names:
            failures.append(f"unexpected reachable capability: {short_item(item)}")
    return failures


def highest_severity(bom: dict[str, object]) -> str:
    rank = 0
    for _source, _item, severity in severity_items(bom):
        rank = max(rank, severity_rank(severity))
    return SEVERITY_BY_RANK[rank]


def severity_items(bom: dict[str, object]) -> list[tuple[str, dict[str, object], str]]:
    items: list[tuple[str, dict[str, object], str]] = []
    repository_risk = bom.get("repository_risk")
    if isinstance(repository_risk, dict):
        severity = str(repository_risk.get("severity", "none"))
        items.append(("repository_risk", repository_risk, severity))

    for source in ("risks", "policy_findings", "secret_leak_findings"):
        for item in list_items(bom, source):
            items.append((source, item, str(item.get("severity", "none"))))

    for item in list_items(bom, "reachable_capabilities"):
        items.append(("reachable_capabilities", item, str(item.get("risk", "none"))))

    for item in list_items(bom, "mcp_servers"):
        items.append(("mcp_servers", item, str(item.get("risk", "none"))))

    review = bom.get("policy_review")
    if isinstance(review, dict):
        for section in ("violations", "warnings"):
            source = f"policy_review.{section}"
            values = review.get(section, [])
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        items.append((source, item, str(item.get("severity", "none"))))
    return items


def any_signal_exists(bom: dict[str, object], signals: list[str]) -> bool:
    return any(signal_items(bom, signal) for signal in signals)


def signal_items(bom: dict[str, object], signal: str) -> list[tuple[str, dict[str, object]]]:
    matches = []
    needle = signal.lower()
    for source, item in signal_bearing_items(bom):
        if needle in signal_haystack(source, item):
            matches.append((source, item))
    return matches


def matching_source_path_exists(
    bom: dict[str, object], signals: list[str], expected_path: str
) -> bool:
    if not signals:
        return False
    for signal in signals:
        for _source, item in signal_items(bom, signal):
            if item_source_path(item) == expected_path:
                return True
    return False


def signal_bearing_items(bom: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    items: list[tuple[str, dict[str, object]]] = []
    for source in (
        "models",
        "providers",
        "frameworks",
        "mcp_servers",
        "prompts",
        "capabilities",
        "dependencies",
        "reachable_capabilities",
        "policy_findings",
        "secret_references",
        "secret_leak_findings",
        "risks",
    ):
        for item in list_items(bom, source):
            items.append((source, item))
    repository_risk = bom.get("repository_risk")
    if isinstance(repository_risk, dict):
        items.append(("repository_risk", repository_risk))
    review = bom.get("policy_review")
    if isinstance(review, dict):
        for section in ("violations", "warnings"):
            values = review.get(section, [])
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        items.append((f"policy_review.{section}", item))
    return items


def signal_haystack(source: str, item: dict[str, object]) -> str:
    return " ".join([source, *flatten_strings(item)]).lower()


def list_items(bom: dict[str, object], key: str) -> list[dict[str, object]]:
    value = bom.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def flatten_strings(value: object) -> list[str]:
    if isinstance(value, dict):
        strings = []
        for key, nested in value.items():
            strings.append(str(key))
            strings.extend(flatten_strings(nested))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(flatten_strings(item))
        return strings
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    return []


def item_source_path(item: dict[str, object]) -> str:
    for key in ("path", "source_file", "source"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""


def raw_value_failures(case: dict[str, Any], bom: dict[str, object]) -> list[str]:
    serialized = json.dumps(bom, sort_keys=True)
    failures = []
    for value in case.get("raw_values_absent", []):
        raw_value = str(value)
        if raw_value and raw_value in serialized:
            failures.append(f"raw sensitive value appeared in serialized output: {raw_value}")
    return failures


def first_expected_signal(case: dict[str, Any]) -> str:
    expected = case.get("expected_any", [])
    if isinstance(expected, list) and expected:
        return str(expected[0])
    return "-"


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.lower(), 0)


def short_item(item: dict[str, object]) -> str:
    text = json.dumps(item, sort_keys=True)
    if len(text) <= 160:
        return text
    return text[:157] + "..."


def main() -> int:
    cases = load_cases()
    results = [evaluate_case(case) for case in cases]

    case_width = max(len("case"), *(len(result.case) for result in results))
    kind_width = max(len("kind"), *(len(result.kind) for result in results))
    result_width = len("result")
    highest_width = len("highest")
    print(
        f"{'case':<{case_width}}  {'kind':<{kind_width}}  "
        f"{'result':<{result_width}}  {'highest':<{highest_width}}  expected signal"
    )
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.case:<{case_width}}  {result.kind:<{kind_width}}  "
            f"{status:<{result_width}}  {result.highest:<{highest_width}}  "
            f"{result.expected_signal}"
        )

    failures = [result for result in results if not result.passed]
    if failures:
        print("")
        for result in failures:
            print(f"{result.case}:")
            for failure in result.failures:
                print(f"  - {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
