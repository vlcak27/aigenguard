"""Command line interface for AgentBOM."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .cyclonedx import write_cyclonedx_report
from .diff import attach_diff, has_new_findings_at_or_above, load_baseline_report, valid_severities
from .github_summary import write_github_step_summary
from .html_report import write_html_report
from .mermaid import write_mermaid_report
from .report import write_reports
from .sarif import write_sarif_report
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentbom",
        description=(
            "Generate offline bill-of-materials and attack-surface reports "
            "for AI-agent repositories."
        ),
        epilog=(
            "Examples:\n"
            "  agentbom scan examples/simple_agent --pretty\n"
            "  agentbom scan . --output-dir agentbom-report --html --mermaid --sarif\n"
            "  agentbom scan . --policy agentbom.toml --sarif --pretty"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"agentbom {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="scan a repository",
        description=(
            "Scan source and configuration files offline without executing "
            "project code.\n"
            "JSON and Markdown reports are always written."
        ),
        epilog=(
            "Common workflows:\n"
            "  agentbom scan . --pretty\n"
            "  agentbom scan . --output-dir agentbom-report --html --mermaid\n"
            "  agentbom scan . --baseline agentbom-baseline.json --fail-on-new high --sarif"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument("path", help="repository directory to scan")
    scan_parser.add_argument(
        "--output-dir",
        default=".",
        help="directory for generated reports (default: current directory)",
    )
    scan_parser.add_argument("--policy", help="AgentBOM TOML policy file")
    scan_parser.add_argument(
        "--enforce-policy",
        action="store_true",
        help="exit nonzero when --policy produces policy violations",
    )
    diff_group = scan_parser.add_argument_group("diff and policy gates")
    diff_group.add_argument("--baseline", help="baseline agentbom.json report for diff output")
    diff_group.add_argument(
        "--fail-on-new",
        choices=valid_severities(),
        help="exit nonzero when introduced diff findings meet or exceed this severity",
    )
    scan_parser.add_argument("--pretty", action="store_true", help="pretty-print JSON reports")
    output_group = scan_parser.add_argument_group("optional reports")
    output_group.add_argument(
        "--cyclonedx",
        action="store_true",
        help="write agentbom.cdx.json dependency inventory",
    )
    output_group.add_argument(
        "--html",
        action="store_true",
        help="write self-contained offline agentbom.html",
    )
    output_group.add_argument(
        "--mermaid",
        action="store_true",
        help="write agentbom.mmd capability graph",
    )
    output_group.add_argument("--sarif", action="store_true", help="write agentbom.sarif")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.fail_on_new and not args.baseline:
            parser.error("--fail-on-new requires --baseline PATH")
        try:
            bom = scan_path(
                args.path,
                policy_path=args.policy,
                enforce_policy=args.enforce_policy,
            )
            if args.baseline:
                attach_diff(bom, load_baseline_report(args.baseline))
            json_path, md_path = write_reports(bom, Path(args.output_dir), pretty=args.pretty)
            cyclonedx_path = None
            html_path = None
            mermaid_path = None
            sarif_path = None
            if args.cyclonedx:
                cyclonedx_path = write_cyclonedx_report(
                    bom, Path(args.output_dir), pretty=args.pretty
                )
            if args.html:
                html_path = write_html_report(bom, Path(args.output_dir))
            if args.mermaid:
                mermaid_path = write_mermaid_report(bom, Path(args.output_dir))
            if args.sarif:
                sarif_path = write_sarif_report(bom, Path(args.output_dir), pretty=args.pretty)
            output_paths = [json_path, md_path]
            for path in (cyclonedx_path, html_path, mermaid_path, sarif_path):
                if path is not None:
                    output_paths.append(path)
            write_github_step_summary(bom, output_paths)
        except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as exc:
            print(f"agentbom: {exc}", file=sys.stderr)
            return 1
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        if cyclonedx_path is not None:
            print(f"Wrote {cyclonedx_path}")
        if html_path is not None:
            print(f"Wrote {html_path}")
        if mermaid_path is not None:
            print(f"Wrote {mermaid_path}")
        if sarif_path is not None:
            print(f"Wrote {sarif_path}")
        risk = bom.get("repository_risk", {})
        if isinstance(risk, dict):
            severity = risk.get("severity", "unknown")
            score = risk.get("score", "unknown")
            print(f"Risk: {severity} ({score}/100)")
        policy_review = bom.get("policy_review")
        if isinstance(policy_review, dict):
            _print_policy_review(policy_review)
        diff = bom.get("diff", {})
        if isinstance(diff, dict) and args.fail_on_new:
            if has_new_findings_at_or_above(diff, args.fail_on_new):
                print(
                    f"New findings at or above {args.fail_on_new} severity were introduced.",
                    file=sys.stderr,
                )
                return 1
        if isinstance(policy_review, dict) and args.enforce_policy:
            if policy_review.get("violations"):
                return 1
        return 0

    parser.error("unknown command")
    return 2


def _print_policy_review(policy_review: dict[str, object]) -> None:
    status = _policy_review_status(policy_review)
    print("")
    print(f"Policy review: {status}")
    print(f"Mode: {policy_review.get('mode', 'advisory')}")
    policy_file = policy_review.get("policy_file")
    if policy_file:
        print(f"Policy file: {policy_file}")
    violations = _policy_items(policy_review.get("violations"))
    warnings = _policy_items(policy_review.get("warnings"))
    if violations:
        print("")
        print("Violations:")
        for item in violations:
            print(f"- {item.get('severity', 'low')}: {item.get('message', '')}")
    if warnings:
        print("")
        print("Warnings:")
        for item in warnings:
            print(f"- {item.get('severity', 'low')}: {item.get('message', '')}")
    if policy_review.get("mode") == "advisory" and violations:
        print("")
        print("Policy violations do not fail the scan unless --enforce-policy is used.")


def _policy_items(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _policy_review_status(policy_review: dict[str, object]) -> str:
    if policy_review.get("violations"):
        return "failed"
    if policy_review.get("warnings"):
        return "passed with warnings"
    return "passed"


if __name__ == "__main__":
    raise SystemExit(main())
