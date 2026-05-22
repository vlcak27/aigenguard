"""Command line interface for AgentBOM."""

from __future__ import annotations

import argparse
import shlex
import sys
import webbrowser
from pathlib import Path

from . import __version__
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
from .report import write_reports
from .runbom import configure_runbom, detect_runbom_command, run_runbom
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
            "Recommended workflow:\n"
            "  agentbom activate\n"
            "  git commit\n"
            "  agentbom run\n"
            "  agentbom scan . --policy agentbom.toml --html --open\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"agentbom {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="create a starter agentbom.toml policy",
        description="Create a starter AgentBOM TOML policy in the current directory.",
        epilog=(
            "Examples:\n"
            "  agentbom init\n"
            "  agentbom init --output agentbom-starter.toml"
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
            "  agentbom init\n"
            "  agentbom scan . --policy agentbom.toml --html --open\n"
            "  agentbom scan . --suggest-policy agentbom.toml\n"
            "  agentbom scan . --policy agentbom.toml --enforce-policy\n"
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
        help="evaluate an AgentBOM TOML policy file in advisory mode by default",
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
        help="activate the repo-local AgentBOM guard",
        description=(
            "Create or reuse agentbom.toml and install a repo-local pre-commit "
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
        default="agentbom.toml",
        help="AgentBOM TOML policy file relative to the repository root (default: agentbom.toml)",
    )
    activate_parser.add_argument(
        "--preset",
        choices=POLICY_PRESETS,
        default=None,
        help="policy preset when creating agentbom.toml (default: safe)",
    )
    activate_parser.add_argument(
        "--strict",
        action="store_true",
        help="compatibility alias for --preset strict",
    )
    activate_parser.add_argument(
        "--append",
        action="store_true",
        help="append the managed AgentBOM block to an existing non-AgentBOM hook",
    )
    activate_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing policy or hook content where supported",
    )
    activate_parser.add_argument(
        "--agentbom-command",
        default="agentbom",
        help="agentbom executable path for the hook to call (default: agentbom)",
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
            "Run the configured RunBOM runtime command from agentbom.toml without a shell. "
            "Configure a direct command like: pytest, python -m pytest, or npm test."
        ),
    )

    subparsers.add_parser(
        "status",
        help="show repo-local AgentBOM guard status",
        description="Show whether the current repository has an AgentBOM local guard installed.",
    )

    subparsers.add_parser(
        "deactivate",
        help="deactivate the repo-local AgentBOM guard",
        description=(
            "Remove the AgentBOM managed block from .git/hooks/pre-commit. "
            "The policy file is kept."
        ),
    )

    guard_parser = subparsers.add_parser(
        "guard",
        help="run the local policy guard used by pre-commit hooks",
        description=(
            "Run an AgentBOM policy guard without writing reports into the repository. "
            "Modes: advisory warns and allows, confirm asks before committing, "
            "enforce blocks policy violations."
        ),
    )
    guard_parser.add_argument("path", help="repository directory to scan")
    guard_parser.add_argument(
        "--policy",
        required=True,
        help="AgentBOM TOML policy file",
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

    install_parser = subparsers.add_parser(
        "install-hook",
        help="install a repo-local pre-commit policy guard",
        description=(
            "Install an AgentBOM managed block in .git/hooks/pre-commit. "
            "Modes: advisory warns and allows, confirm asks before committing, "
            "enforce blocks policy violations."
        ),
    )
    install_parser.add_argument(
        "--policy",
        default="agentbom.toml",
        help="AgentBOM TOML policy file relative to the repository root (default: agentbom.toml)",
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
        help="append the managed AgentBOM block to an existing non-AgentBOM hook",
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing non-AgentBOM pre-commit hook",
    )
    install_parser.add_argument(
        "--agentbom-command",
        default="agentbom",
        help="agentbom executable path for the hook to call (default: agentbom)",
    )

    subparsers.add_parser(
        "uninstall-hook",
        help="remove the AgentBOM managed pre-commit hook block",
        description="Remove the AgentBOM managed block from .git/hooks/pre-commit.",
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
        _print_scan_next_steps(
            args=args,
            output_dir=json_path.parent,
            html_path=html_path,
            browser_opened=browser_opened,
            policy_review=policy_review if isinstance(policy_review, dict) else None,
            suggested_policy_path=suggested_policy_path,
        )
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

    if args.command == "activate":
        return _activate(args)

    if args.command == "run":
        return run_runbom()

    if args.command == "status":
        return _print_status()

    if args.command == "deactivate":
        return _deactivate()

    if args.command == "guard":
        return run_guard(args.path, args.policy, args.mode)

    if args.command == "install-hook":
        if args.mode and args.enforce_policy:
            parser.error("install-hook: --mode and --enforce-policy cannot be used together")
        mode = "enforce" if args.enforce_policy else (args.mode or "advisory")
        try:
            hook_path = install_hook(
                args.policy,
                mode,
                agentbom_command=args.agentbom_command,
                append=True,
                force=args.force,
            )
        except ExistingHookError as exc:
            print(f"agentbom: {exc}", file=sys.stderr)
            print(
                "Use --append to keep existing hook content or --force to overwrite it.",
                file=sys.stderr,
            )
            return 1
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            print(f"agentbom: {exc}", file=sys.stderr)
            return 1
        print(f"Installed AgentBOM pre-commit hook at {hook_path}")
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
        print(f"agentbom: {exc}", file=sys.stderr)
        return 1
    try:
        repo_root, _git_dir = find_git_root()
        if has_unmanaged_hook(cwd=repo_root) and not args.append and not args.force:
            print(
                "agentbom: existing non-AgentBOM pre-commit hook found: "
                ".git/hooks/pre-commit",
                file=sys.stderr,
            )
            print("Use one of:", file=sys.stderr)
            print(
                f"  agentbom install-hook --append --policy {args.policy} --mode {args.mode}",
                file=sys.stderr,
            )
            print("  agentbom activate --append", file=sys.stderr)
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
            agentbom_command=args.agentbom_command,
            append=args.append,
            force=args.force,
            cwd=repo_root,
        )
    except ExistingHookError as exc:
        print(f"agentbom: {exc}", file=sys.stderr)
        print("Use agentbom activate --append to keep existing hook content.", file=sys.stderr)
        return 1
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        print(f"agentbom: {exc}", file=sys.stderr)
        return 1

    print("AgentBOM activated")
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
    print("  agentbom run")
    print("  agentbom status")
    print(f"  agentbom scan . --policy {args.policy} --html --open")
    return 0


def _activation_preset(args: argparse.Namespace) -> str:
    if args.strict and args.preset and args.preset != "strict":
        raise ValueError("--strict cannot be combined with --preset other than strict")
    if args.strict:
        return "strict"
    return args.preset or "safe"


def _print_status() -> int:
    status = local_guard_status()
    print("AgentBOM status")
    print("")
    if not status.repository_detected:
        print("Repository: not detected")
        print("Policy: missing")
        print("Local guard: not installed")
        print("")
        print("Next:")
        print("  cd path/to/your-agent-repo")
        print("  agentbom activate")
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
        print("  agentbom activate")
    return 0


def _deactivate() -> int:
    try:
        repo_root, _git_dir = find_git_root()
        status = local_guard_status(cwd=repo_root)
        hook_path = uninstall_hook(cwd=repo_root)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"agentbom: {exc}", file=sys.stderr)
        return 1
    if hook_path is None:
        print("AgentBOM local guard is not installed.")
    else:
        print("AgentBOM deactivated for this repository.")
        print("")
        print("Policy kept:")
        print(f"  {status.policy or 'agentbom.toml'}")
    return 0


def _uninstall_hook() -> int:
    try:
        hook_path = uninstall_hook()
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"agentbom: {exc}", file=sys.stderr)
        return 1
    if hook_path is None:
        print("No AgentBOM managed pre-commit hook block found.")
    else:
        print(f"Removed AgentBOM pre-commit hook block from {hook_path}")
    return 0


def _repo_policy_path(repo_root: Path, policy: str) -> Path:
    policy_path = Path(policy)
    if policy_path.is_absolute():
        return policy_path
    return repo_root / policy_path


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
) -> None:
    print("")
    print(f"Reports written to: {_display_dir(output_dir)}")
    if html_path is not None:
        print("")
        if args.open and browser_opened:
            print("Opened HTML report:")
            print(f"  {html_path}")
        else:
            print("HTML report:")
            print(f"  {html_path}")
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
    policy_path = Path(args.path) / "agentbom.toml"
    print("")
    print("Next:")
    if not args.html:
        print("  Open HTML report:")
        print(f"    {_scan_command(args, html=True, open_report=True)}")
        print("")
    if policy_path.exists():
        print("  Use existing policy:")
        print(
            f"    {_scan_command(args, policy=policy_path, html=True, open_report=True)}"
        )
    else:
        print("  Start policy review:")
        print("    agentbom init")
        print(
            f"    {_scan_command(args, policy=Path('agentbom.toml'), html=True, open_report=True)}"
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
    parts = ["agentbom", "scan", str(args.path)]
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
    raise SystemExit(cli())
