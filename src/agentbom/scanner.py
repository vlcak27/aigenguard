"""Repository scanner for AgentBOM v0.1."""

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
    validate_custom_policy,
    validate_policies,
)
from .reachability import detect_reachable_capability_hits, infer_reachable_capabilities
from .risk import score_repository_risk, score_risks


MAX_FILE_SIZE = 1_000_000
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
        "generated_by": "agentbom",
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
    policy_file = Path(policy_path) if policy_path is not None else None
    if policy_file is not None and policy_file.suffix.lower() != ".toml":
        for finding in validate_custom_policy(policy_path, bom, has_human_approval):
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
