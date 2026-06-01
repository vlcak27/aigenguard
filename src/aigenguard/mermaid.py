"""Mermaid capability graph export for AigenGuard."""

from __future__ import annotations

import hashlib
from html import escape
from pathlib import Path
import re
from typing import Any


SEVERITIES = ("low", "medium", "high", "critical")
CAPABILITY_SEVERITY = {
    "autonomous_execution": "high",
    "cloud": "medium",
    "cloud_access": "medium",
    "code_execution": "high",
    "database": "medium",
    "mcp_tool_invocation": "medium",
    "filesystem_access": "high",
    "shell_process_execution": "high",
    "browser_network_access": "medium",
    "database_access": "medium",
    "secrets_env_access": "high",
    "unknown_custom_server": "low",
    "network": "medium",
    "network_access": "medium",
    "shell": "high",
    "shell_execution": "high",
}


def write_mermaid_report(bom: dict[str, Any], output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    mermaid_path = out / "agentbom.mmd"
    mermaid_path.write_text(render_mermaid(bom), encoding="utf-8")
    return mermaid_path


def render_mermaid(bom: dict[str, Any]) -> str:
    graph = MermaidGraph()
    _add_finding_nodes(graph, "provider", "Provider", bom.get("providers", []))
    _add_model_nodes(graph, bom.get("models", []))
    _add_finding_nodes(graph, "framework", "Framework", bom.get("frameworks", []))
    _add_mcp_nodes(graph, bom.get("mcp_servers", []))
    _add_capability_nodes(graph, bom.get("capabilities", []))
    _add_reachable_nodes(graph, bom.get("reachable_capabilities", []))
    _add_policy_nodes(graph, bom.get("policy_findings", []), bom.get("capabilities", []))
    _add_provider_edges(graph, bom.get("providers", []), bom.get("models", []))
    _add_reachability_edges(
        graph,
        bom.get("models", []),
        bom.get("frameworks", []),
        bom.get("mcp_servers", []),
        bom.get("reachable_capabilities", []),
    )
    _add_mcp_edges(graph, bom.get("mcp_servers", []))
    return graph.render()


class MermaidGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, str]] = {}
        self._edges: set[tuple[str, str, str]] = set()

    def add_node(self, key: str, label: str, severity: str) -> str:
        node_id = _node_id(key)
        self._nodes[node_id] = {
            "key": key,
            "label": label,
            "severity": _severity(severity),
        }
        return node_id

    def add_edge(self, source_key: str, target_key: str, label: str) -> None:
        source = _node_id(source_key)
        target = _node_id(target_key)
        if source in self._nodes and target in self._nodes:
            self._edges.add((source, target, label))

    def render(self) -> str:
        lines = ["flowchart TD"]
        lines.extend(_class_definitions())
        for node_id, node in sorted(self._nodes.items(), key=lambda item: item[1]["key"]):
            lines.append(f'  {node_id}["{_label(node["label"])}"]')
            lines.append(f"  class {node_id} {node['severity']}")
        for source, target, label in sorted(self._edges):
            lines.append(f"  {source} -- {_edge_label(label)} --> {target}")
        return "\n".join(lines) + "\n"


def _add_finding_nodes(
    graph: MermaidGraph,
    node_type: str,
    title: str,
    findings: object,
) -> None:
    if not isinstance(findings, list):
        return
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        name = str(finding.get("name", "unknown"))
        graph.add_node(f"{node_type}:{name}", f"{title}: {name}", "low")


def _add_model_nodes(graph: MermaidGraph, models: object) -> None:
    if not isinstance(models, list):
        return
    for model in models:
        if not isinstance(model, dict):
            continue
        name = str(model.get("name", "unknown"))
        graph.add_node(f"model:{name}", f"Model: {name}", "low")


def _add_capability_nodes(graph: MermaidGraph, capabilities: object) -> None:
    if not isinstance(capabilities, list):
        return
    for capability in capabilities:
        if not isinstance(capability, dict):
            continue
        name = str(capability.get("name", "unknown"))
        graph.add_node(
            f"capability:{name}",
            f"Capability: {name}",
            CAPABILITY_SEVERITY.get(name, "low"),
        )


def _add_mcp_nodes(graph: MermaidGraph, mcp_servers: object) -> None:
    if not isinstance(mcp_servers, list):
        return
    for server in mcp_servers:
        if not isinstance(server, dict):
            continue
        if server.get("kind") != "server":
            continue
        name = str(server.get("name", "unknown"))
        risk = str(server.get("risk", "low"))
        graph.add_node(f"mcp_server:{name}", f"MCP Server: {name}", risk)
        graph.add_node(
            "capability:mcp_tool_invocation",
            "Capability: mcp_tool_invocation",
            "medium",
        )
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            category_name = str(category)
            graph.add_node(
                f"mcp_risk:{category_name}",
                f"MCP Risk: {category_name}",
                CAPABILITY_SEVERITY.get(category_name, "low"),
            )


def _add_reachable_nodes(graph: MermaidGraph, reachable_capabilities: object) -> None:
    if not isinstance(reachable_capabilities, list):
        return
    for reachable in reachable_capabilities:
        if not isinstance(reachable, dict):
            continue
        actor = str(reachable.get("reachable_from", "unknown"))
        capability = str(reachable.get("capability", "unknown"))
        source_file = str(reachable.get("source_file", "unknown"))
        key = f"reachable:{actor}:{capability}:{source_file}"
        label = f"Reachable: {actor} -> {capability}\n{source_file}"
        graph.add_node(
            f"capability:{capability}",
            f"Capability: {capability}",
            CAPABILITY_SEVERITY.get(capability, str(reachable.get("risk", "low"))),
        )
        graph.add_node(key, label, str(reachable.get("risk", "low")))


def _add_policy_nodes(
    graph: MermaidGraph,
    policy_findings: object,
    capabilities: object,
) -> None:
    if not isinstance(policy_findings, list):
        return
    capability_keys_by_path = _capability_keys_by_path(capabilities)
    for finding in policy_findings:
        if not isinstance(finding, dict):
            continue
        message = str(finding.get("message", "policy finding"))
        source_file = str(finding.get("source_file", "unknown"))
        severity = str(finding.get("severity", "low"))
        key = f"policy:{severity}:{source_file}:{message}"
        graph.add_node(key, f"Policy: {message}\n{source_file}", severity)
        for capability_key in capability_keys_by_path.get(source_file, []):
            graph.add_edge(capability_key, key, "policy")


def _add_provider_edges(
    graph: MermaidGraph,
    providers: object,
    models: object,
) -> None:
    if not isinstance(providers, list) or not isinstance(models, list):
        return
    provider_items = [item for item in providers if isinstance(item, dict)]
    model_items = [item for item in models if isinstance(item, dict)]
    for model in model_items:
        model_name = str(model.get("name", "unknown"))
        source_file = model.get("source_file")
        matches = [provider for provider in provider_items if provider.get("path") == source_file]
        if not matches and len(provider_items) == 1:
            matches = provider_items
        for provider in matches:
            graph.add_edge(f"model:{model_name}", f"provider:{provider.get('name', 'unknown')}", "uses")


def _add_reachability_edges(
    graph: MermaidGraph,
    models: object,
    frameworks: object,
    mcp_servers: object,
    reachable_capabilities: object,
) -> None:
    if not isinstance(reachable_capabilities, list):
        return
    model_names = _names(models)
    framework_names = _names(frameworks)
    mcp_names = _names(mcp_servers)
    for reachable in reachable_capabilities:
        if not isinstance(reachable, dict):
            continue
        actor = str(reachable.get("reachable_from", "unknown"))
        capability = str(reachable.get("capability", "unknown"))
        source_file = str(reachable.get("source_file", "unknown"))
        reachable_key = f"reachable:{actor}:{capability}:{source_file}"
        capability_key = f"capability:{capability}"
        if actor in model_names:
            graph.add_edge(f"model:{actor}", reachable_key, "reaches")
        if actor in framework_names:
            graph.add_edge(f"framework:{actor}", reachable_key, "reaches")
            graph.add_edge(f"framework:{actor}", capability_key, "enables")
        server = str(reachable.get("mcp_server", ""))
        if server in mcp_names:
            graph.add_edge(f"mcp_server:{server}", reachable_key, "reachable")
        graph.add_edge(reachable_key, capability_key, "reaches")


def _add_mcp_edges(graph: MermaidGraph, mcp_servers: object) -> None:
    if not isinstance(mcp_servers, list):
        return
    for server in mcp_servers:
        if not isinstance(server, dict):
            continue
        if server.get("kind") != "server":
            continue
        name = str(server.get("name", "unknown"))
        graph.add_edge(f"mcp_server:{name}", "capability:mcp_tool_invocation", "exposes")
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            graph.add_edge(f"mcp_server:{name}", f"mcp_risk:{category}", "risk")


def _capability_keys_by_path(capabilities: object) -> dict[str, list[str]]:
    keys_by_path: dict[str, list[str]] = {}
    if not isinstance(capabilities, list):
        return keys_by_path
    for capability in capabilities:
        if not isinstance(capability, dict):
            continue
        path = str(capability.get("path", ""))
        name = str(capability.get("name", "unknown"))
        if path:
            keys_by_path.setdefault(path, [])
            _append_unique(keys_by_path[path], f"capability:{name}")
    return keys_by_path


def _names(items: object) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {str(item.get("name")) for item in items if isinstance(item, dict) and item.get("name")}


def _node_id(key: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_]+", "_", key).strip("_").lower()
    if not slug:
        slug = "node"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
    return f"{slug}_{digest}"


def _label(value: str) -> str:
    return escape(value, quote=True).replace("\n", "<br/>")


def _edge_label(value: str) -> str:
    return escape(value, quote=True)


def _severity(value: str) -> str:
    if value in SEVERITIES:
        return value
    return "low"


def _class_definitions() -> list[str]:
    return [
        "  classDef low fill:#eef8f0,stroke:#2e7d32,color:#123d1c",
        "  classDef medium fill:#fff8e1,stroke:#f9a825,color:#4a3500",
        "  classDef high fill:#ffebee,stroke:#c62828,color:#4a0707",
        "  classDef critical fill:#3b0d0d,stroke:#b71c1c,color:#ffffff",
    ]


def _append_unique(items: list[str], item: str) -> None:
    if item not in items:
        items.append(item)
