"""Command line interface for AgentBOM."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .cyclonedx import write_cyclonedx_report
from .diff import attach_diff, has_new_findings_at_or_above, load_baseline_report, valid_severities
from .github_summary import write_github_step_summary
from .html_report import write_html_report
from .mermaid import write_mermaid_report
from .policy_onboarding import (
    next_steps,
    starter_policy_toml,
    suggested_policy_toml,
    write_policy_file,
)
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
            "  agentbom init\n"
            "  agentbom scan examples/simple_agent --pretty\n"
            "  agentbom scan . --policy agentbom.toml --html --open\n"
            "  agentbom scan . --suggest-policy agentbom.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"agentbom {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="create a starter agentbom.toml policy",
        description="Create a starter AgentBOM TOML policy in the current directory.",
    )
    init_parser.add_argument(
        "--strict",
        action="store_true",
        help="write a stricter starter policy; review advisory results before enforcing",
    )
    init_parser.add_argument(
        "--output",
        default="agentbom.toml",
        help="policy path to write (default: agentbom.toml)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite the policy file if it already exists",
    )

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
            "  agentbom scan . --policy agentbom.toml --html --open\n"
            "  agentbom scan . --suggest-policy agentbom.toml\n"
            "  agentbom scan . --policy agentbom.toml --enforce-policy"
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
    scan_parser.add_argument(
        "--suggest-policy",
        metavar="PATH",
        help="write a starter policy from scan findings without enforcing it",
    )
    scan_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite the --suggest-policy path if it already exists",
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
        "--open",
        action="store_true",
        help="write HTML if needed and open agentbom.html in a browser",
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

    if args.command == "init":
        try:
            path = write_policy_file(
                args.output,
                starter_policy_toml(strict=args.strict),
                force=args.force,
            )
        except FileExistsError:
            print(
                f"agentbom: policy file already exists: {args.output}",
                file=sys.stderr,
            )
            print("Use --force to overwrite it or --output PATH for another file.", file=sys.stderr)
            return 1
        print(f"Created {path}")
        if args.strict:
            print("Strict starter policy written. Run advisory mode before enforcement.")
        _print_next_steps(path)
        return 0

    if args.command == "scan":
        if args.fail_on_new and not args.baseline:
            parser.error("--fail-on-new requires --baseline PATH")
        if args.open:
            args.html = True
        if args.suggest_policy and Path(args.suggest_policy).exists() and not args.force:
            print(
                f"agentbom: policy file already exists: {args.suggest_policy}",
                file=sys.stderr,
            )
            print(
                "Use --force to overwrite it or choose another --suggest-policy path.",
                file=sys.stderr,
            )
            return 1
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
            suggested_policy_path = None
            if args.suggest_policy:
                suggested_policy_path = write_policy_file(
                    args.suggest_policy,
                    suggested_policy_toml(bom),
                    force=args.force,
                )
            if args.mermaid:
                mermaid_path = write_mermaid_report(bom, Path(args.output_dir))
            if args.sarif:
                sarif_path = write_sarif_report(bom, Path(args.output_dir), pretty=args.pretty)
            output_paths = [json_path, md_path]
            for path in (cyclonedx_path, html_path, mermaid_path, sarif_path):
                if path is not None:
                    output_paths.append(path)
            write_github_step_summary(bom, output_paths)
            browser_opened = False
            browser_error = None
            if args.open and html_path is not None:
                try:
                    browser_opened = webbrowser.open(html_path.resolve().as_uri())
                except Exception as exc:  # noqa: BLE001
                    browser_error = exc
        except FileExistsError as exc:
            print(
                f"agentbom: policy file already exists: {exc}",
                file=sys.stderr,
            )
            print(
                "Use --force to overwrite it or choose another --suggest-policy path.",
                file=sys.stderr,
            )
            return 1
        except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as exc:
            print(f"agentbom: {exc}", file=sys.stderr)
            return 1
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        if cyclonedx_path is not None:
            print(f"Wrote {cyclonedx_path}")
        if html_path is not None:
            print(f"Wrote {html_path}")
            if args.open:
                print(f"HTML report: {html_path}")
                if browser_error is not None:
                    print(
                        f"Could not open browser automatically: {browser_error}",
                        file=sys.stderr,
                    )
                elif not browser_opened:
                    print(
                        "Could not confirm browser opened automatically.",
                        file=sys.stderr,
                    )
        if mermaid_path is not None:
            print(f"Wrote {mermaid_path}")
        if sarif_path is not None:
            print(f"Wrote {sarif_path}")
        if suggested_policy_path is not None:
            print("")
            print(f"Suggested policy written to {suggested_policy_path}")
            _print_next_steps(suggested_policy_path)
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


def _print_next_steps(policy_path: str | Path) -> None:
    print("")
    print("Next:")
    for command in next_steps(policy_path):
        print(f"  {command}")


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
