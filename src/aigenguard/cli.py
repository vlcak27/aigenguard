"""Command line interface for AigenGuard."""

from __future__ import annotations

import argparse
import shlex
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .blocked_output import format_blocked_details
from .cyclonedx import write_cyclonedx_report
from .diff import attach_diff, has_new_findings_at_or_above, load_baseline_report, valid_severities
from .github_summary import write_github_step_summary
from .html_report import write_html_report
from .local_guard import (
    GUARD_MODES,
    ExistingHookError,
    find_git_root,
    has_unmanaged_hook,
    install_hook,
    local_guard_status,
    run_guard,
    uninstall_hook,
)
from .mermaid import write_mermaid_report
from .policy_onboarding import (
    POLICY_PRESETS,
    next_steps,
    starter_policy_toml,
    suggested_policy_toml,
    write_policy_file,
)
from .policy_paths import DEFAULT_POLICY_NAME, discover_policy_path, preferred_policy_path
from .report import write_reports
from .runbom import configure_runbom, detect_runbom_command, run_runbom
from .sarif import write_sarif_report
from .scanner import scan_path
from .terminal import TerminalStyle, terminal_style


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Local-first pre-commit policy guard for AI-agent repositories. "
            "Previously AgentBOM."
        ),
        epilog=(
            "Recommended workflow:\n"
            "  aigenguard activate\n"
            "  git commit\n"
            "  aigenguard scan . --policy aigenguard.toml --html --open\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"aigenguard {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="create a starter aigenguard.toml policy",
        description="Create a starter AigenGuard TOML policy in the current directory.",
        epilog=(
            "Examples:\n"
            "  aigenguard init\n"
            "  aigenguard init --output aigenguard-starter.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_parser.add_argument(
        "--strict",
        action="store_true",
        help="write a stricter starter policy; review advisory results before enforcing",
    )
    init_parser.add_argument(
        "--output",
        default=DEFAULT_POLICY_NAME,
        help=f"policy path to write (default: {DEFAULT_POLICY_NAME})",
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
            "  aigenguard scan . --pretty\n"
            "  aigenguard init\n"
            "  aigenguard scan . --policy aigenguard.toml --html --open\n"
            "  aigenguard scan . --suggest-policy aigenguard.toml\n"
            "  aigenguard scan . --policy aigenguard.toml --enforce-policy\n"
            "\n"
            "Policy review is advisory by default. Add --enforce-policy only after review.\n"
            "--open opens the generated HTML report. --suggest-policy writes a starter\n"
            "policy from the current findings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument("path", help="repository directory to scan")
    scan_parser.add_argument(
        "--output-dir",
        default=".",
        help="directory for generated reports (default: current directory)",
    )
    scan_parser.add_argument(
        "--policy",
        help="evaluate a TOML policy file in advisory mode by default",
    )
    scan_parser.add_argument(
        "--enforce-policy",
        action="store_true",
        help="opt in to nonzero exit when --policy produces policy violations",
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
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in terminal output",
    )
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
        help="write HTML if needed and open the generated agentbom.html in a browser",
    )
    output_group.add_argument(
        "--mermaid",
        action="store_true",
        help="write agentbom.mmd capability graph",
    )
    output_group.add_argument("--sarif", action="store_true", help="write agentbom.sarif")

    activate_parser = subparsers.add_parser(
        "activate",
        help="activate the repo-local AigenGuard policy guard",
        description=(
            "Create or reuse aigenguard.toml, with agentbom.toml fallback, and install a repo-local pre-commit "
            "guard. Configure RunBOM when possible. Default mode is confirm."
        ),
    )
    activate_parser.add_argument(
        "--mode",
        choices=GUARD_MODES,
        default="confirm",
        help="local guard mode (default: confirm)",
    )
    activate_parser.add_argument(
        "--policy",
        default=None,
        help="policy file relative to the repository root (default: discover aigenguard.toml, then agentbom.toml)",
    )
    activate_parser.add_argument(
        "--preset",
        choices=POLICY_PRESETS,
        default=None,
        help="policy preset when creating aigenguard.toml (default: safe)",
    )
    activate_parser.add_argument(
        "--strict",
        action="store_true",
        help="compatibility alias for --preset strict",
    )
    activate_parser.add_argument(
        "--append",
        action="store_true",
        help="append the managed AigenGuard block to an existing non-AigenGuard hook",
    )
    activate_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing policy or hook content where supported",
    )
    activate_parser.add_argument(
        "--aigenguard-command",
        "--agentbom-command",
        dest="aigenguard_command",
        default="aigenguard",
        help="AigenGuard executable path for the hook to call (default: aigenguard)",
    )
    activate_parser.add_argument(
        "--command",
        dest="runbom_command",
        help=(
            "RunBOM direct command to configure; executed without a shell. "
            "Examples: pytest, python -m pytest, npm test"
        ),
    )
    activate_parser.add_argument(
        "--no-runbom",
        action="store_true",
        help="skip RunBOM configuration setup",
    )

    subparsers.add_parser(
        "run",
        help="run RunBOM runtime verification",
        description=(
            "Run the configured RunBOM runtime command from aigenguard.toml or agentbom.toml without a shell. "
            "Configure a direct command like: pytest, python -m pytest, or npm test."
        ),
    )

    subparsers.add_parser(
        "status",
        help="show repo-local AigenGuard policy guard status",
        description="Show whether the current repository has an AigenGuard local guard installed.",
    )

    subparsers.add_parser(
        "deactivate",
        help="deactivate the repo-local AigenGuard policy guard",
        description=(
            "Remove the AigenGuard managed block from .git/hooks/pre-commit. "
            "The policy file is kept."
        ),
    )

    guard_parser = subparsers.add_parser(
        "guard",
        help="run the local policy guard used by pre-commit hooks",
        description=(
            "Run an AigenGuard policy guard without writing reports into the repository. "
            "Modes: advisory warns and allows, confirm asks before committing, "
            "enforce blocks policy violations."
        ),
    )
    guard_parser.add_argument("path", help="repository directory to scan")
    guard_parser.add_argument(
        "--policy",
        required=True,
        help="AigenGuard TOML policy file",
    )
    guard_parser.add_argument(
        "--mode",
        choices=GUARD_MODES,
        default="advisory",
        help=(
            "local guard mode: advisory warns and allows, confirm asks, "
            "enforce blocks (default: advisory)"
        ),
    )
    guard_parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in terminal output",
    )

    install_parser = subparsers.add_parser(
        "install-hook",
        help="install a repo-local pre-commit policy guard",
        description=(
            "Install an AigenGuard managed block in .git/hooks/pre-commit. "
            "Modes: advisory warns and allows, confirm asks before committing, "
            "enforce blocks policy violations."
        ),
    )
    install_parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_NAME,
        help=f"policy file relative to the repository root (default: {DEFAULT_POLICY_NAME})",
    )
    install_parser.add_argument(
        "--mode",
        choices=GUARD_MODES,
        help=(
            "local guard mode: advisory warns and allows, confirm asks, "
            "enforce blocks (default: advisory)"
        ),
    )
    install_parser.add_argument(
        "--enforce-policy",
        action="store_true",
        help="compatibility alias for --mode enforce",
    )
    install_parser.add_argument(
        "--append",
        action="store_true",
        help="append the managed AigenGuard block to an existing non-AigenGuard hook",
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing non-AigenGuard pre-commit hook",
    )
    install_parser.add_argument(
        "--aigenguard-command",
        "--agentbom-command",
        dest="aigenguard_command",
        default="aigenguard",
        help="AigenGuard executable path for the hook to call (default: aigenguard)",
    )

    subparsers.add_parser(
        "uninstall-hook",
        help="remove the AigenGuard managed pre-commit hook block",
        description="Remove the AigenGuard managed block from .git/hooks/pre-commit.",
    )
    return parser


def cli(argv: list[str] | None = None) -> int:
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
                f"aigenguard: policy file already exists: {args.output}",
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
        style = terminal_style(no_color=args.no_color)
        if args.fail_on_new and not args.baseline:
            parser.error("--fail-on-new requires --baseline PATH")
        if args.open:
            args.html = True
        if args.suggest_policy and Path(args.suggest_policy).exists() and not args.force:
            print(
                f"aigenguard: policy file already exists: {args.suggest_policy}",
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
                f"aigenguard: policy file already exists: {exc}",
                file=sys.stderr,
            )
            print(
                "Use --force to overwrite it or choose another --suggest-policy path.",
                file=sys.stderr,
            )
            return 1
        except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as exc:
            print(f"aigenguard: {exc}", file=sys.stderr)
            return 1
        policy_review = bom.get("policy_review")
        policy_blocked = (
            isinstance(policy_review, dict)
            and args.enforce_policy
            and bool(_policy_items(policy_review.get("violations")))
        )
        diff = bom.get("diff", {})
        diff_blocked = (
            isinstance(diff, dict)
            and args.fail_on_new
            and has_new_findings_at_or_above(diff, args.fail_on_new)
        )
        if not policy_blocked:
            _print_scan_completion(
                policy_review=policy_review if isinstance(policy_review, dict) else None,
                diff_blocked=bool(diff_blocked),
                style=style,
            )
            print("")
        print(f"Wrote {style.cyan(json_path)}")
        print(f"Wrote {style.cyan(md_path)}")
        if cyclonedx_path is not None:
            print(f"Wrote {style.cyan(cyclonedx_path)}")
        if html_path is not None:
            print(f"Wrote {style.cyan(html_path)}")
            if args.open and browser_error is not None:
                print(
                    f"Could not open browser automatically: {browser_error}",
                    file=sys.stderr,
                )
            elif args.open and not browser_opened:
                print(
                    "Could not confirm browser opened automatically.",
                    file=sys.stderr,
                )
        if mermaid_path is not None:
            print(f"Wrote {style.cyan(mermaid_path)}")
        if sarif_path is not None:
            print(f"Wrote {style.cyan(sarif_path)}")
        if suggested_policy_path is not None:
            print("")
            print(f"Suggested policy written to {style.cyan(suggested_policy_path)}")
            _print_next_steps(suggested_policy_path)
        risk = bom.get("repository_risk", {})
        if isinstance(risk, dict):
            severity = risk.get("severity", "unknown")
            score = risk.get("score", "unknown")
            print(f"Risk: {_format_risk_value(severity, style)} ({score}/100)")
        if isinstance(policy_review, dict):
            _print_policy_review(policy_review, include_items=not policy_blocked, style=style)
        if policy_blocked:
            print("")
            print(style.red("AigenGuard blocked this policy-enforced scan."))
            print("")
            print(format_blocked_details(bom, html_path=html_path, style=style))
        else:
            _print_scan_next_steps(
                args=args,
                output_dir=json_path.parent,
                html_path=html_path,
                browser_opened=browser_opened,
                policy_review=policy_review if isinstance(policy_review, dict) else None,
                suggested_policy_path=suggested_policy_path,
                style=style,
            )
        if diff_blocked:
            print(
                f"New findings at or above {args.fail_on_new} severity were introduced.",
                file=sys.stderr,
            )
            return 1
        if isinstance(policy_review, dict) and args.enforce_policy:
            if policy_review.get("violations"):
                return 1
        return 0

    if args.command == "activate":
        return _activate(args)

    if args.command == "run":
        return run_runbom()

    if args.command == "status":
        return _print_status()

    if args.command == "deactivate":
        return _deactivate()

    if args.command == "guard":
        return run_guard(args.path, args.policy, args.mode, no_color=args.no_color)

    if args.command == "install-hook":
        if args.mode and args.enforce_policy:
            parser.error("install-hook: --mode and --enforce-policy cannot be used together")
        mode = "enforce" if args.enforce_policy else (args.mode or "advisory")
        try:
            hook_path = install_hook(
                args.policy,
                mode,
                aigenguard_command=args.aigenguard_command,
                append=True,
                force=args.force,
            )
        except ExistingHookError as exc:
            print(f"aigenguard: {exc}", file=sys.stderr)
            print(
                "Use --append to keep existing hook content or --force to overwrite it.",
                file=sys.stderr,
            )
            return 1
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            print(f"aigenguard: {exc}", file=sys.stderr)
            return 1
        print(f"Installed AigenGuard pre-commit hook at {hook_path}")
        print(f"Guard mode: {mode}")
        return 0

    if args.command == "uninstall-hook":
        return _uninstall_hook()

    parser.error("unknown command")
    return 2


def main(argv: list[str] | None = None) -> int:
    return cli(argv)


def _activate(args: argparse.Namespace) -> int:
    try:
        preset = _activation_preset(args)
    except ValueError as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        return 1
    try:
        repo_root, _git_dir = find_git_root()
        args.policy = _activation_policy(repo_root, args.policy)
        if has_unmanaged_hook(cwd=repo_root) and not args.append and not args.force:
            print(
                "aigenguard: existing non-AigenGuard pre-commit hook found: "
                ".git/hooks/pre-commit",
                file=sys.stderr,
            )
            print("Use one of:", file=sys.stderr)
            print(
                f"  aigenguard install-hook --append --policy {args.policy} --mode {args.mode}",
                file=sys.stderr,
            )
            print("  aigenguard activate --append", file=sys.stderr)
            return 1

        policy_file = _repo_policy_path(repo_root, args.policy)
        if args.force or not policy_file.exists():
            write_policy_file(
                policy_file,
                starter_policy_toml(preset=preset),
                force=args.force,
            )
        if not args.no_runbom:
            runbom_command = args.runbom_command or detect_runbom_command(repo_root)
            configure_runbom(policy_file, runbom_command, force=args.force)
        install_hook(
            args.policy,
            args.mode,
            aigenguard_command=args.aigenguard_command,
            append=args.append,
            force=args.force,
            cwd=repo_root,
        )
    except ExistingHookError as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        print("Use aigenguard activate --append to keep existing hook content.", file=sys.stderr)
        return 1
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        return 1

    print("AigenGuard activated")
    print("")
    print(f"Policy: {args.policy}")
    print(f"Preset: {preset}")
    print(f"Guard mode: {args.mode}")
    print("")
    print("Protected:")
    print("- AI/API secret leak policy")
    print("- shell/code execution policy")
    print("- MCP server policy")
    print("- risky reachable capability policy")
    print("")
    print("Next:")
    print("  git commit")
    print("  aigenguard run")
    print("  aigenguard status")
    print(f"  aigenguard scan . --policy {args.policy} --html --open")
    return 0


def _activation_preset(args: argparse.Namespace) -> str:
    if args.strict and args.preset and args.preset != "strict":
        raise ValueError("--strict cannot be combined with --preset other than strict")
    if args.strict:
        return "strict"
    return args.preset or "safe"


def _print_status() -> int:
    try:
        status = local_guard_status()
    except ValueError as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        return 1
    print("AigenGuard status")
    print("")
    if not status.repository_detected:
        print("Repository: not detected")
        print("Policy: missing")
        print("Local guard: not installed")
        print("")
        print("Next:")
        print("  cd path/to/your-agent-repo")
        print("  aigenguard activate")
        return 0

    print("Repository: detected")
    if status.policy_exists and status.policy:
        print(f"Policy: {status.policy}")
    elif status.policy:
        print(f"Policy: missing ({status.policy})")
    else:
        print("Policy: missing")
    if status.hook_installed:
        print("Local guard: active")
        if status.mode:
            print(f"Mode: {status.mode}")
        if status.hook_path is not None and status.repo_root is not None:
            print(f"Hook: {_display_path(status.hook_path, status.repo_root)}")
    else:
        print("Local guard: not installed")
        print("")
        print("Next:")
        print("  aigenguard activate")
    return 0


def _deactivate() -> int:
    try:
        repo_root, _git_dir = find_git_root()
        status = local_guard_status(cwd=repo_root)
        hook_path = uninstall_hook(cwd=repo_root)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        return 1
    if hook_path is None:
        print("AigenGuard local guard is not installed.")
    else:
        print("AigenGuard deactivated for this repository.")
        print("")
        print("Policy kept:")
        print(f"  {status.policy or DEFAULT_POLICY_NAME}")
    return 0


def _uninstall_hook() -> int:
    try:
        hook_path = uninstall_hook()
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"aigenguard: {exc}", file=sys.stderr)
        return 1
    if hook_path is None:
        print("No AigenGuard managed pre-commit hook block found.")
    else:
        print(f"Removed AigenGuard pre-commit hook block from {hook_path}")
    return 0


def _repo_policy_path(repo_root: Path, policy: str) -> Path:
    policy_path = Path(policy)
    if policy_path.is_absolute():
        return policy_path
    return repo_root / policy_path


def _activation_policy(repo_root: Path, policy: str | None) -> str:
    policy_path = preferred_policy_path(repo_root) if policy is None else Path(policy)
    return _display_path(policy_path, repo_root)


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def _print_next_steps(policy_path: str | Path) -> None:
    print("")
    print("Next:")
    for command in next_steps(policy_path):
        print(f"  {command}")


def _print_scan_next_steps(
    *,
    args: argparse.Namespace,
    output_dir: Path,
    html_path: Path | None,
    browser_opened: bool,
    policy_review: dict[str, object] | None,
    suggested_policy_path: Path | None,
    style: TerminalStyle,
) -> None:
    print("")
    print(f"Reports written to: {style.cyan(_display_dir(output_dir))}")
    if html_path is not None:
        print("")
        if args.open and browser_opened:
            print("Opened HTML report:")
            print(f"  {style.cyan(html_path)}")
        else:
            print("HTML report:")
            print(f"  {style.cyan(html_path)}")
            print("")
            print("Open it:")
            print(f"  {_scan_command(args, html=True, open_report=True)}")
    if suggested_policy_path is not None:
        return
    if policy_review is None:
        _print_no_policy_next_steps(args)
        return
    _print_policy_next_steps(args, policy_review)


def _print_no_policy_next_steps(args: argparse.Namespace) -> None:
    policy_path = discover_policy_path(args.path)
    print("")
    print("Next:")
    if not args.html:
        print("  Open HTML report:")
        print(f"    {_scan_command(args, html=True, open_report=True)}")
        print("")
    if policy_path is not None:
        print("  Use existing policy:")
        print(
            f"    {_scan_command(args, policy=policy_path, html=True, open_report=True)}"
        )
    else:
        print("  Start policy review:")
        print("    aigenguard init")
        print(
            f"    {_scan_command(args, policy=Path(DEFAULT_POLICY_NAME), html=True, open_report=True)}"
        )


def _print_policy_next_steps(args: argparse.Namespace, policy_review: dict[str, object]) -> None:
    status = _policy_review_status(policy_review)
    mode = str(policy_review.get("mode", "advisory"))
    policy_path = Path(str(policy_review.get("policy_file") or args.policy))
    print("")
    print("Next:")
    if mode == "enforced":
        if status == "failed":
            print("  Policy enforcement failed. Fix policy violations before committing/merging.")
        else:
            suffix = " with warnings" if status == "passed with warnings" else ""
            print(f"  Policy enforcement passed{suffix}.")
        return
    print("  Review policy findings in the report.")
    if status == "failed":
        print(f"  Update {policy_path.as_posix()}, then run advisory mode again.")
    print("")
    print("  Enforce after review:")
    print(f"    {_scan_command(args, policy=policy_path, enforce_policy=True)}")


def _scan_command(
    args: argparse.Namespace,
    *,
    policy: Path | None = None,
    html: bool = False,
    open_report: bool = False,
    enforce_policy: bool = False,
) -> str:
    parts = ["aigenguard", "scan", str(args.path)]
    if args.output_dir != ".":
        parts.extend(["--output-dir", str(args.output_dir)])
    if policy is not None:
        parts.extend(["--policy", policy.as_posix()])
    if html:
        parts.append("--html")
    if open_report:
        parts.append("--open")
    if enforce_policy:
        parts.append("--enforce-policy")
    return " ".join(shlex.quote(part) for part in parts)


def _display_dir(path: Path) -> str:
    value = path.as_posix()
    if value in {"", "."}:
        return "."
    return value.rstrip("/") + "/"


def _print_policy_review(
    policy_review: dict[str, object],
    *,
    include_items: bool = True,
    style: TerminalStyle,
) -> None:
    status = _policy_review_status(policy_review)
    print("")
    print(f"{style.bold('Policy review')}: {_format_policy_status(status, style)}")
    print(f"Mode: {policy_review.get('mode', 'advisory')}")
    policy_file = policy_review.get("policy_file")
    if policy_file:
        print(f"Policy file: {style.cyan(policy_file)}")
    if not include_items:
        return
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
        print(style.dim("Policy violations do not fail the scan unless --enforce-policy is used."))


def _print_scan_completion(
    *,
    policy_review: dict[str, object] | None,
    diff_blocked: bool,
    style: TerminalStyle,
) -> None:
    if _has_advisory_policy_violations(policy_review):
        print(style.yellow("AigenGuard scan completed with review findings."))
        print(style.dim("Run with --enforce-policy to block policy violations."))
        return
    if _has_policy_warnings(policy_review) or diff_blocked:
        print(style.yellow("AigenGuard scan completed with review findings."))
        return
    print(style.green("AigenGuard scan completed."))
    print("No blocking findings found.")


def _has_advisory_policy_violations(policy_review: dict[str, object] | None) -> bool:
    return (
        policy_review is not None
        and policy_review.get("mode") == "advisory"
        and bool(_policy_items(policy_review.get("violations")))
    )


def _has_policy_warnings(policy_review: dict[str, object] | None) -> bool:
    return policy_review is not None and bool(_policy_items(policy_review.get("warnings")))


def _format_policy_status(status: str, style: TerminalStyle) -> str:
    if status == "failed":
        return style.red(status)
    if status == "passed with warnings":
        return style.yellow(status)
    return style.green(status)


def _format_risk_value(severity: object, style: TerminalStyle) -> str:
    value = str(severity)
    lowered = value.lower()
    if lowered == "critical":
        return style.red(value)
    if lowered in {"high", "medium"}:
        return style.yellow(value)
    if lowered == "low":
        return style.green(value)
    return value


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
    raise SystemExit(cli())
