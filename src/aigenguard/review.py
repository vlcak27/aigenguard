"""Review immutable Git data using the existing scanner and policy evaluator."""

from __future__ import annotations

from contextlib import ExitStack
import html
import json
from pathlib import Path, PurePosixPath
import tomllib

from . import __version__
from .detectors import POLICY_NAMES
from .diff import diff_reports, SEVERITY_ORDER
from .git_index import git_output, review_snapshot
from .mcp import _extract_server_definitions, is_mcp_config_path
from .policy import DEFAULT_TOML_POLICY, _normalize_reachable_capability, evaluate_policy, normalize_toml_policy
from .scanner import IGNORE_DIRS, iter_scannable_files, _scan_path
from .security_changes import change, safe_text


REVIEW_SCHEMA_VERSION = "1.1"


def empty_review() -> dict:
    return {
        "schema_version": REVIEW_SCHEMA_VERSION, "tool": {"name": "aigenguard", "version": __version__},
        "status": "incomplete", "snapshots": {"base": {"kind": "unavailable"}, "candidate": {"kind": "unavailable"}},
        "mcp_changes": [], "policy_changes": [],
        "baseline_policy": {"status": "not_evaluated", "violations": [], "warnings": []},
        "coverage": {
            "supported": ["JSON MCP configurations", "AigenGuard TOML policy", "base-policy evaluation"],
            "not_evaluated": ["runtime access or exploitability", "MCP client Roots", "filesystem symlinks",
                              "environment values", "arbitrary server argument semantics",
                              "runtime sandboxing", "non-JSON MCP configuration",
                              "source files in scanner-excluded directories or unsupported file types"],
            "issues": [],
        },
    }


def _issue(report, snapshot, file, reason):
    report["coverage"]["issues"].append({"snapshot": snapshot, "file": safe_text(file), "reason": reason})


def _policy(snapshot: Path, skipped: list[dict], explicit: str | None):
    skipped_names = {item["file"] for item in skipped}
    names = [explicit] if explicit else ["aigenguard.toml", "agentbom.toml"]
    name = next((name for name in names if name in skipped_names or (snapshot / name).exists()), names[0])
    if name in skipped_names:
        return name, None, "policy is not a scannable regular file"
    path = snapshot / name
    if not path.exists():
        return name, None, "policy is missing"
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        normalized = normalize_toml_policy(raw)
    except (ValueError, OSError):
        return name, None, "policy is invalid or unsupported TOML"
    # Normalize exactly as the evaluator does, including ignored capability aliases.
    for section, defaults in DEFAULT_TOML_POLICY.items():
        for key in defaults:
            value = normalized[section][key]
            if isinstance(value, list):
                if section == "capabilities":
                    value = [_normalize_reachable_capability(item) for item in value]
                else:
                    value = [item.strip().lower() for item in value]
                normalized[section][key] = sorted({item for item in value if item})
    return name, normalized, None


def _set_direction(old, new):
    return ("no_effect" if old == new else "expanded" if new > old else
            "narrowed" if old > new else "review_required")


def compare_policy(before: dict, after: dict, file: str) -> list[dict]:
    findings = []
    for section, defaults in DEFAULT_TOML_POLICY.items():
        for field in defaults:
            a, b = before[section][field], after[section][field]
            if a == b:
                continue
            kind = "review_required"
            if section in {"providers", "models", "frameworks", "mcp"} and isinstance(a, list):
                allow_key = "allow_servers" if section == "mcp" else "allow"
                deny_key = "deny_servers" if section == "mcp" else "deny"
                names = {None}
                for rules in (before[section], after[section]):
                    names.update(rules[allow_key] + rules[deny_key])

                def permitted(rules):
                    allow, deny = set(rules[allow_key]), set(rules[deny_key])
                    return {name for name in names if name not in deny and (not allow or name in allow)}

                kind = _set_direction(permitted(before[section]), permitted(after[section]))
            elif isinstance(a, list):
                kind = _set_direction(set(b), set(a))  # fewer denials = broader access
            elif isinstance(a, bool):
                kind = "expanded" if a and not b else "narrowed"
            elif field == "warn_on":
                rank_a, rank_b = SEVERITY_ORDER.get(a, 5), SEVERITY_ORDER.get(b, 5)
                kind = "expanded" if rank_b > rank_a else "narrowed"
            why = {
                "expanded": "Effective policy became less restrictive.",
                "narrowed": "Effective policy became more restrictive.",
                "no_effect": "The changed field does not alter effective permitted names.",
                "review_required": "Policy both permits and restricts different names; review the tradeoff.",
            }[kind]
            if section in {"models", "providers", "frameworks"} or field in {"allow_servers", "deny_servers"}:
                why += " Empty allowlists impose no allow restriction; deny takes precedence. Impact includes both lists."
            elif field == "block_leaks":
                why += " Detected secret leaks are " + ("blocking." if b else "no longer blocking under this rule.")
            elif field == "require_policy_for_risky_servers":
                why += " The risky-server policy-evidence requirement is " + ("enabled." if b else "disabled.")
            elif section == "capabilities":
                why += " The set of denied statically reachable capabilities changed."
            else:
                why += " The threshold or visibility of static findings changed."
            findings.append(change(
                f"policy.{section}.{field}", "policy", file, f"/{section}/{field}", kind,
                _safe_values(a), _safe_values(b),
                why,
                "Confirm this policy change is intended; retain the original restrictions otherwise.",
                "high" if kind == "expanded" and section != "policy_gaps" and field not in {"warn_on_detected", "warn_on_unknown_server"}
                else "medium" if kind in {"expanded", "review_required"} else "low",
                "high" if kind != "review_required" else "unknown",
                identity=[a, b],
            ))
    return findings


def _safe_values(value):
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, list):
        return [_safe_values(item) for item in value]
    return value


def _mcp_issues(report, root, label):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if path.name.lower() in {".mcp.yaml", ".mcp.yml", "mcp.yaml", "mcp.yml", ".mcp.toml", "mcp.toml"}:
            _issue(report, label, relative, "non-JSON MCP configuration is unsupported")
        if not is_mcp_config_path(relative):
            continue
        if any(part in IGNORE_DIRS for part in PurePosixPath(relative).parts):
            _issue(report, label, relative, "MCP config is in a scanner-excluded directory")
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
            containers = []
            if isinstance(raw, dict):
                for owner in [raw, *[raw.get(key) for key in ("mcp", "modelContextProtocol", "model_context_protocol")]]:
                    if isinstance(owner, dict):
                        containers.extend(owner[key] for key in ("mcpServers", "mcp_servers", "servers")
                                          if key in owner)
            if not containers or any(not isinstance(item, (dict, list)) for item in containers):
                raise ValueError("unsupported structure")
            definitions = _extract_server_definitions(raw)
            pointers = [(pointer.rsplit("/", 1)[0], name) for name, _, pointer in definitions]
            if len(set(pointers)) != len(pointers):
                raise ValueError("duplicate server identity")
        except (ValueError, OSError, RecursionError):
            _issue(report, label, relative, "invalid, ambiguous, or unsupported JSON MCP configuration")


def review_repository(repo: str | Path, *, base: str, head: str | None = None,
                      staged: bool = False, policy: str | None = None) -> dict:
    report = empty_review()
    try:
        if staged == (head is not None):
            raise ValueError("choose exactly one candidate: --staged or --head")
        if policy is not None:
            path = PurePosixPath(policy)
            if (path.is_absolute() or ".." in path.parts or "\\" in policy or ":" in policy
                    or path.suffix != ".toml"):
                raise ValueError("policy must be a repository-relative TOML path without parent traversal")
        root = Path(git_output(Path(repo), "rev-parse", "--show-toplevel").decode().strip())
        with ExitStack() as stack:
            snapshots = []
            for label, ref in (("base", base), ("candidate", None if staged else head)):
                snapshot = stack.enter_context(review_snapshot(root, ref=ref, label=label))
                report["snapshots"][label] = snapshot[1]
                snapshots.append(snapshot)
            reports, policies = [], []
            for label, (directory, descriptor, skipped) in zip(("base", "candidate"), snapshots):
                report["snapshots"][label] = descriptor
                name, rules, error = _policy(directory, skipped, policy)
                policies.append((name, rules))
                if error:
                    _issue(report, label, name, error)
                for item in skipped:
                    # Any non-binary skipped data may affect original-policy evaluation.
                    if item["reason"] != "binary file" or is_mcp_config_path(item["file"]) or item["file"] == name:
                        _issue(report, label, item["file"], item["reason"] + "; original-policy coverage excludes this entry")
                _mcp_issues(report, directory, label)
                bom = _scan_path(directory, policy_path=directory / name, evaluate_rules=False)
                for server in bom["mcp_servers"]:
                    if server.get("kind") == "server" and not server.get("security_config", {}).get("complete"):
                        _issue(report, label, str(server["path"]), "unsupported MCP server definition")
                reports.append(bom)
            report["mcp_changes"] = diff_reports(*reports)["security_changes"]
            (base_name, base_policy), (head_name, head_policy) = policies
            if base_policy is not None and head_policy is not None:
                report["policy_changes"] = compare_policy(base_policy, head_policy, head_name)
            elif base_policy is not None:
                report["policy_changes"] = [change(
                    "policy.availability", "policy", head_name, "/", "removed",
                    "valid policy", "missing or invalid", "Candidate policy was removed or is not evaluable.",
                    "Restore a valid staged policy and review intended rule changes.", "high", "high")]
            if base_name != head_name:
                report["policy_changes"].append(change(
                    "policy.location", "policy", head_name, "/", "review_required",
                    safe_text(base_name), safe_text(head_name), "The selected policy file changed.",
                    "Review policy precedence and the policy path used by your hook."))
            if base_policy is not None:
                directory = snapshots[1][0]
                evidence = any(path.name.lower() in POLICY_NAMES for path in iter_scannable_files(directory))
                original = evaluate_policy(base_policy, reports[1], has_repository_policy=evidence)
                result = report["baseline_policy"]
                result.update(status="evaluated", file=safe_text(base_name))
                for kind in ("violations", "warnings"):
                    result[kind] = [change(
                        "baseline." + item["rule"], "baseline-policy", str(item.get("source", "")),
                        "/" + item["rule"].replace(".", "/"), "violation" if kind == "violations" else "review_required",
                        {"rule": item["rule"]},
                        {"evidence": safe_text(item["message"]),
                         **({"line": int(item["line"])} if str(item.get("line", "")).isdigit() else {})},
                        item["message"], item["suggested_remediation"],
                        item["severity"], "high", identity=item,
                    ) for item in original[kind]]
            report["status"] = "incomplete" if report["coverage"]["issues"] else "complete"
    except (OSError, ValueError, RecursionError) as exc:
        report["status"] = "error"
        # Known operational messages only: never echo parsers, paths, or raw configuration.
        message = str(exc)
        allowed = ("invalid base reference", "invalid candidate reference", "base commit is unavailable",
                   "candidate commit is unavailable", "choose exactly", "policy must be", "unmerged index",
                   "snapshot contains", "snapshot paths collide", "snapshot blob unavailable", "Git ")
        report["error"] = message if message.startswith(allowed) else "snapshot review failed; check repository access and input encoding"
    return report


def review_findings(report):
    return [*report["mcp_changes"], *report["policy_changes"],
            *report["baseline_policy"]["violations"], *report["baseline_policy"]["warnings"]]


def review_exit_code(report, fail_on: str | None = None) -> int:
    if report["status"] != "complete":
        return 2
    if fail_on and any(item["change"] not in {"no_effect", "narrowed", "removed"}
                       and SEVERITY_ORDER[item["severity"]] >= SEVERITY_ORDER[fail_on]
                       for item in review_findings(report)):
        return 1
    return 0


def terminal_review(report) -> str:
    findings = review_findings(report)
    lines = [f"AigenGuard review: {report['status']}; {len(findings)} change/review finding(s)."]
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = sorted(findings, key=lambda item: priority[item["severity"]])
    for item in findings[:8]:
        lines.append(f"{item['severity'].upper()} {item['rule_id']} [{item['change']}] {item['file']} {item['field']}")
        lines.append("  " + item["explanation"])
        lines.append("  " + json.dumps(item["before"], ensure_ascii=True) + " -> " + json.dumps(item["after"], ensure_ascii=True))
    if len(findings) > 8:
        lines.append(f"{len(findings) - 8} more finding(s) in the reports.")
    for issue in report["coverage"]["issues"][:5]:
        lines.append(f"INCOMPLETE {issue['snapshot']}: {issue['file']}: {issue['reason']}")
    if "error" in report:
        lines.append(report["error"])
    return "\n".join(lines)


def markdown_review(report) -> str:
    def escaped(value):
        return html.escape(str(value)).replace("`", "&#96;").replace("|", "&#124;").replace("[", "&#91;")

    lines = ["# AigenGuard configuration review", "", f"Status: **{report['status']}**",
             f"Tool: aigenguard {report['tool']['version']}; review schema {report['schema_version']}", "",
             "Configured access is not proof of runtime access or an exploit.", "",
             "## Snapshots", "", "```json", json.dumps(report["snapshots"], sort_keys=True, indent=2), "```"]
    for title, items in (("MCP configuration", report["mcp_changes"]),
                         ("Policy changes", report["policy_changes"]),
                         ("Original policy violations", report["baseline_policy"]["violations"]),
                         ("Original policy warnings", report["baseline_policy"]["warnings"])):
        lines.extend(["", "## " + title, ""])
        if not items:
            lines.append("No findings in this section; see completeness and coverage below.")
        if title == "Original policy warnings" and items:
            lines.append("Candidate warnings under the original policy; these may predate this PR. "
                         "Credential references are not confirmed leaks. Full evidence and IDs remain "
                         "in aigenguard-review.json; grouping does not change exit decisions.")
            groups = {}
            for item in items:
                groups.setdefault((item["severity"], item["rule_id"]), []).append(item)
            for (severity, rule), group in sorted(groups.items()):
                lines.append(f"- **{severity.upper()} {escaped(rule)}: {len(group)} warning(s)**")
                for item in group[:3]:
                    lines.append(f"  - {escaped(item['file'])}: {escaped(item['explanation'])}")
                if len(group) > 3:
                    lines.append(f"  - {len(group) - 3} further warning(s) in JSON.")
                lines.append("  - Review: " + escaped(group[0]["recommendation"]))
            continue
        for item in items:
            lines.extend([f"- **{item['severity'].upper()} {item['rule_id']} — {item['change']}**",
                          f"  - Component: {escaped(item['component'])}; file: {escaped(item['file'])}; field: {escaped(item['field'])}",
                          f"  - Before: {escaped(json.dumps(item['before'], ensure_ascii=True))}",
                          f"  - After: {escaped(json.dumps(item['after'], ensure_ascii=True))}",
                          f"  - {escaped(item['explanation'])}", f"  - Review: {escaped(item['recommendation'])}",
                          f"  - Change confidence: {item['change_confidence']}; impact confidence: {item['impact_confidence']}"])
    lines.extend(["", "## Coverage", "", f"Original policy evaluation: {report['baseline_policy']['status']}",
                  "Supported: " + "; ".join(report["coverage"]["supported"]),
                  "Not evaluated: " + "; ".join(report["coverage"]["not_evaluated"])])
    lines.extend(f"- INCOMPLETE {issue['snapshot']}: {escaped(issue['file'])}: {issue['reason']}"
                 for issue in report["coverage"]["issues"])
    if any(issue["snapshot"] == "base" and issue["reason"] == "policy is missing"
           for issue in report["coverage"]["issues"]):
        lines.extend(["", "### Establish a trusted baseline", "",
                      "On the protected base branch, run `aigenguard init` to draft a policy. "
                      "Review and set the allowed/denied providers, models, capabilities and MCP servers "
                      "with the maintainers; an empty allowlist is unrestricted. Commit the approved "
                      "policy through normal review before comparing subsequent PRs. Select that "
                      "commit as the baseline. Adding policy only in the candidate does not fix a "
                      "missing baseline. No policy was automatically trusted or generated here."])
    if "error" in report:
        lines.append(escaped(report["error"]))
    return "\n".join(lines) + "\n"


def write_review(report: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "aigenguard-review.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (output / "aigenguard-review.md").write_text(markdown_review(report), encoding="utf-8")
