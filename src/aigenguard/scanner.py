"""Repository scanner for AigenGuard v0.1."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION
from .detectors import detect_in_file, sort_secret_leak_findings
from .graph import build_capability_graph
from .policy import (
    evaluate_policy_file,
    has_human_approval_text,
    normalize_capability,
    validate_custom_policy,
    validate_policies,
)
from .policy_paths import MAX_POLICY_FILE_SIZE, discover_policy_path
from .reachability import detect_reachable_capability_hits, infer_reachable_capabilities
from .risk import score_repository_risk, score_risks


MAX_FILE_SIZE = MAX_POLICY_FILE_SIZE
IGNORE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".ini",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".ts",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {
    ".env.example",
    ".gitignore",
    "Dockerfile",
    "Makefile",
    "requirements.txt",
}


def scan_path(
    path: str | Path,
    policy_path: str | Path | None = None,
    *,
    enforce_policy: bool = False,
) -> dict[str, object]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"path is not a directory: {root}")

    bom: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "repository": str(root),
        "generated_by": "aigenguard",
        "models": [],
        "providers": [],
        "frameworks": [],
        "mcp_servers": [],
        "prompts": [],
        "capabilities": [],
        "dependencies": [],
        "reachable_capabilities": [],
        "capability_graph": {"nodes": [], "edges": []},
        "policy_findings": [],
        "repository_risk": {"score": 0, "severity": "low", "rationale": []},
        "secret_references": [],
        "secret_leak_findings": [],
        "risks": [],
    }
    has_policy = False
    has_human_approval = False
    reachable_capability_hits: list[dict[str, Any]] = []

    for file_path in iter_scannable_files(root):
        relpath = file_path.relative_to(root).as_posix()
        text = read_text_file(file_path)
        result = detect_in_file(relpath, text)
        has_policy = has_policy or result.has_policy
        for key, items in result.findings.items():
            for item in items:
                _append_unique(bom[key], item)
        if text is not None:
            has_human_approval = has_human_approval or has_human_approval_text(text)
            reachable_capability_hits.extend(detect_reachable_capability_hits(text, relpath))

    bom["reachable_capabilities"] = infer_reachable_capabilities(
        bom["models"],
        bom["frameworks"],
        bom["mcp_servers"],
        bom["prompts"],
        reachable_capability_hits,  # type: ignore[arg-type]
    )
    bom["capability_graph"] = build_capability_graph(
        bom["providers"],
        bom["models"],
        bom["frameworks"],
        bom["mcp_servers"],
        bom["capabilities"],
        bom["reachable_capabilities"],
        bom["prompts"],
    )  # type: ignore[arg-type]
    bom["risks"] = score_risks(
        bom["capabilities"], bom["prompts"], bom["mcp_servers"], has_policy  # type: ignore[arg-type]
    )
    bom["secret_leak_findings"] = sort_secret_leak_findings(
        bom["secret_leak_findings"]  # type: ignore[arg-type]
    )
    bom["policy_findings"] = validate_policies(
        bom["prompts"], bom["capabilities"], bom["mcp_servers"], has_policy  # type: ignore[arg-type]
    )
    policy_file = discover_policy_path(root, policy_path, max_file_size=MAX_FILE_SIZE)
    if policy_file is not None and policy_file.suffix.lower() != ".toml":
        for finding in validate_custom_policy(policy_file, bom, has_human_approval):
            _append_unique(bom["policy_findings"], finding)
    bom["repository_risk"] = score_repository_risk(
        bom["reachable_capabilities"],
        bom["capabilities"],
        bom["secret_references"],
        bom["policy_findings"],
    )  # type: ignore[arg-type]
    if policy_file is not None and policy_file.suffix.lower() == ".toml":
        bom["policy_review"] = evaluate_policy_file(
            policy_file,
            bom,
            mode="enforced" if enforce_policy else "advisory",
            has_repository_policy=has_policy,
        )
    _annotate_policy_status(bom, has_repository_policy=has_policy)
    return bom


def iter_scannable_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in IGNORE_DIRS and not (Path(dirpath) / name).is_symlink()
        ]
        for filename in sorted(filenames):
            file_path = Path(dirpath) / filename
            if file_path.is_symlink() or not file_path.is_file():
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            if looks_like_text_file(file_path):
                yield file_path


def looks_like_text_file(path: Path) -> bool:
    if path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        sample = path.read_bytes()[:1024]
    except OSError:
        return False
    return b"\0" not in sample


def read_text_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:1024]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def _append_unique(items: list[dict[str, object]], item: dict[str, object]) -> None:
    if item not in items:
        items.append(item)


def _annotate_policy_status(
    bom: dict[str, object], *, has_repository_policy: bool
) -> None:
    """Attach review context without changing detection or enforcement."""
    review_items = _policy_review_items(bom.get("policy_review"))
    policy_findings = _finding_items(bom.get("policy_findings"))
    undocumented_sources = {
        str(item.get("source_file", ""))
        for item in policy_findings
        if _policy_finding_is_gap(item)
    }

    _annotate_policy_findings(policy_findings)
    mcp_statuses = _annotate_mcp_policy_status(
        _finding_items(bom.get("mcp_servers")),
        review_items,
        has_repository_policy=has_repository_policy,
    )
    _annotate_capability_policy_status(
        _finding_items(bom.get("capabilities")),
        review_items,
        undocumented_sources,
        has_repository_policy=has_repository_policy,
    )
    _annotate_reachable_policy_status(
        _finding_items(bom.get("reachable_capabilities")),
        review_items,
        undocumented_sources,
        mcp_statuses,
    )


def _annotate_policy_findings(items: list[dict[str, Any]]) -> None:
    for item in items:
        message = str(item.get("message", "")).lower()
        if message.startswith("custom policy violation:"):
            item["policy_status"] = "policy_violation"
        elif " without " in f" {message} " or "lacks policy evidence" in message:
            item["policy_status"] = "undocumented"


def _annotate_mcp_policy_status(
    items: list[dict[str, Any]],
    review_items: list[dict[str, Any]],
    *,
    has_repository_policy: bool,
) -> dict[tuple[str, str], str]:
    statuses = {}
    for item in items:
        name = str(item.get("name", ""))
        path = str(item.get("path", ""))
        status = _matching_review_status(
            review_items,
            path,
            rule_prefixes=("mcp.",),
            message_terms=(name,),
        )
        if status is None and _mcp_status_from_repository_policy(item):
            status = (
                "documented_by_repository_policy"
                if has_repository_policy
                else "undocumented"
            )
        if status is not None:
            item["policy_status"] = status
            statuses[(path, name)] = status
    return statuses


def _annotate_capability_policy_status(
    items: list[dict[str, Any]],
    review_items: list[dict[str, Any]],
    undocumented_sources: set[str],
    *,
    has_repository_policy: bool,
) -> None:
    for item in items:
        name = str(item.get("name", ""))
        path = str(item.get("path", ""))
        capability = _reachable_capability_name(name)
        terms = (capability,) if capability else ()
        status = _matching_review_status(
            review_items,
            path,
            rule_prefixes=("capabilities.", "policy_gaps."),
            message_terms=terms,
        )
        if status is None and name in {"shell", "cloud"}:
            status = (
                "documented_by_repository_policy"
                if has_repository_policy
                else "undocumented"
            )
        if status is None and path in undocumented_sources and name in {"shell", "cloud"}:
            status = "undocumented"
        if status is not None:
            item["policy_status"] = status


def _annotate_reachable_policy_status(
    items: list[dict[str, Any]],
    review_items: list[dict[str, Any]],
    undocumented_sources: set[str],
    mcp_statuses: dict[tuple[str, str], str],
) -> None:
    for item in items:
        capability = str(item.get("capability", ""))
        source_file = str(item.get("source_file", ""))
        mcp_server = str(item.get("mcp_server", ""))
        status = _matching_review_status(
            review_items,
            source_file,
            rule_prefixes=("capabilities.",),
            message_terms=(capability,),
        )
        if status is None and mcp_server:
            status = _matching_review_status(
                review_items,
                source_file,
                rule_prefixes=("mcp.",),
                message_terms=(mcp_server,),
            )
        if status is None and mcp_server:
            status = mcp_statuses.get((source_file, mcp_server))
        if status is None and source_file in undocumented_sources:
            status = "undocumented"
        if status is not None:
            item["policy_status"] = status


def _matching_review_status(
    review_items: list[dict[str, Any]],
    source: str,
    *,
    rule_prefixes: tuple[str, ...],
    message_terms: tuple[str, ...] = (),
) -> str | None:
    for desired_status in ("policy_violation", "policy_warning"):
        for item in review_items:
            if item.get("policy_status") != desired_status:
                continue
            if source and str(item.get("source", "")) != source:
                continue
            rule = str(item.get("rule", ""))
            if rule_prefixes and not rule.startswith(rule_prefixes):
                continue
            message = str(item.get("message", "")).lower()
            if any(term and term.lower() not in message for term in message_terms):
                continue
            return desired_status
    return None


def _policy_review_items(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    items = []
    for key in ("violations", "warnings"):
        items.extend(_finding_items(value.get(key)))
    return items


def _finding_items(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _policy_finding_is_gap(item: dict[str, Any]) -> bool:
    message = str(item.get("message", "")).lower()
    return " without " in f" {message} " or "lacks policy evidence" in message


def _mcp_status_from_repository_policy(item: dict[str, Any]) -> bool:
    risk = str(item.get("risk", ""))
    categories = item.get("risk_categories", [])
    return risk in {"high", "medium"} or (
        isinstance(categories, list) and "unknown_custom_server" in categories
    )


def _reachable_capability_name(name: str) -> str | None:
    normalized = normalize_capability(name)
    aliases = {
        "shell": "shell_execution",
        "code_execution": "code_execution",
        "cloud": "cloud_access",
        "network": "network_access",
        "database": "database_access",
        "mcp_tool_invocation": "mcp_tool_invocation",
        "autonomous_execution": "autonomous_execution",
    }
    return aliases.get(normalized or name)
