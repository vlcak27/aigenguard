"""Internal capability graph model for AigenGuard."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable


class NodeType:
    PROVIDER = "provider"
    MODEL = "model"
    FRAMEWORK = "framework"
    PROMPT = "prompt"
    MCP_SERVER = "mcp_server"
    CAPABILITY = "capability"
    REACHABLE_CAPABILITY = "reachable_capability"
    MCP_RISK = "mcp_risk"


class EdgeType:
    USES = "uses"
    ENABLES = "enables"
    REACHES = "reaches"
    EXPOSES = "exposes"
    RISK = "risk"


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    name: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "type": self.type, "name": self.name}


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    type: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "target": self.target, "type": self.type}


class CapabilityGraph:
    """Small deterministic directed graph used by report serializers."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: set[GraphEdge] = set()

    def add_node(self, node_type: str, name: str, key: str | None = None) -> str:
        node_id = node_id_for(node_type, name if key is None else key)
        self._nodes[node_id] = GraphNode(id=node_id, type=node_type, name=name)
        return node_id

    def add_edge(self, source: str, target: str, edge_type: str) -> None:
        if source in self._nodes and target in self._nodes:
            self._edges.add(GraphEdge(source=source, target=target, type=edge_type))

    def node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def successors(self, node_id: str, edge_type: str | None = None) -> list[GraphNode]:
        edges = [
            edge
            for edge in self._edges
            if edge.source == node_id and (edge_type is None or edge.type == edge_type)
        ]
        return [
            self._nodes[edge.target]
            for edge in sorted(edges, key=lambda item: (item.target, item.type))
            if edge.target in self._nodes
        ]

    def predecessors(self, node_id: str, edge_type: str | None = None) -> list[GraphNode]:
        edges = [
            edge
            for edge in self._edges
            if edge.target == node_id and (edge_type is None or edge.type == edge_type)
        ]
        return [
            self._nodes[edge.source]
            for edge in sorted(edges, key=lambda item: (item.source, item.type))
            if edge.source in self._nodes
        ]

    def reachable_nodes(
        self,
        start_id: str,
        edge_types: Iterable[str] | None = None,
    ) -> list[GraphNode]:
        allowed_edge_types = set(edge_types) if edge_types is not None else None
        seen = {start_id}
        found: list[GraphNode] = []
        queue: deque[str] = deque([start_id])

        while queue:
            current = queue.popleft()
            edges = [
                edge
                for edge in self._edges
                if edge.source == current
                and (allowed_edge_types is None or edge.type in allowed_edge_types)
            ]
            for edge in sorted(edges, key=lambda item: (item.target, item.type)):
                if edge.target in seen or edge.target not in self._nodes:
                    continue
                seen.add(edge.target)
                found.append(self._nodes[edge.target])
                queue.append(edge.target)

        return found

    def to_dict(self) -> dict[str, list[dict[str, str]]]:
        return {
            "nodes": [
                node.to_dict()
                for node in sorted(self._nodes.values(), key=lambda item: (item.type, item.id))
            ],
            "edges": [
                edge.to_dict()
                for edge in sorted(
                    self._edges,
                    key=lambda item: (item.source, item.target, item.type),
                )
            ],
        }


def build_capability_graph(
    providers: list[dict[str, str]],
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, object]],
    capabilities: list[dict[str, str]],
    reachable_capabilities: list[dict[str, Any]],
    prompts: list[dict[str, str]] | None = None,
) -> dict[str, list[dict[str, str]]]:
    return build_internal_capability_graph(
        providers,
        models,
        frameworks,
        mcp_servers,
        capabilities,
        reachable_capabilities,
        prompts or [],
    ).to_dict()


def build_internal_capability_graph(
    providers: list[dict[str, str]],
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, object]],
    capabilities: list[dict[str, str]],
    reachable_capabilities: list[dict[str, Any]],
    prompts: list[dict[str, str]] | None = None,
) -> CapabilityGraph:
    graph = CapabilityGraph()
    parsed_mcp_servers = _parsed_mcp_servers(mcp_servers)
    prompt_items = prompts or []

    for provider in providers:
        graph.add_node(NodeType.PROVIDER, provider["name"])
    for model in models:
        graph.add_node(NodeType.MODEL, model["name"])
    for framework in frameworks:
        graph.add_node(NodeType.FRAMEWORK, framework["name"])
    for prompt in prompt_items:
        graph.add_node(NodeType.PROMPT, prompt["path"])
    for server in parsed_mcp_servers:
        graph.add_node(NodeType.MCP_SERVER, str(server["name"]))
        graph.add_node(NodeType.CAPABILITY, "mcp_tool_invocation")
    for capability in capabilities:
        graph.add_node(NodeType.CAPABILITY, capability["name"])
    for reachable in reachable_capabilities:
        graph.add_node(NodeType.CAPABILITY, str(reachable["capability"]))
        _add_reachable_node(graph, reachable)
    for server in parsed_mcp_servers:
        categories = server.get("risk_categories", [])
        if isinstance(categories, list):
            for category in categories:
                graph.add_node(NodeType.MCP_RISK, str(category))

    _add_provider_edges(graph, providers, models)
    _add_reachability_edges(graph, models, frameworks, prompt_items, reachable_capabilities)
    _add_mcp_edges(graph, parsed_mcp_servers)
    return graph


def node_id_for(node_type: str, name: str) -> str:
    return f"{node_type}:{name}"


def reachable_node_id(reachable: dict[str, Any]) -> str:
    return node_id_for(
        NodeType.REACHABLE_CAPABILITY,
        "{actor}:{capability}:{source_file}".format(
            actor=reachable["reachable_from"],
            capability=reachable["capability"],
            source_file=reachable["source_file"],
        ),
    )


def _add_reachable_node(graph: CapabilityGraph, reachable: dict[str, Any]) -> str:
    actor = str(reachable["reachable_from"])
    capability = str(reachable["capability"])
    source_file = str(reachable["source_file"])
    return graph.add_node(
        NodeType.REACHABLE_CAPABILITY,
        f"{actor} -> {capability}",
        key=f"{actor}:{capability}:{source_file}",
    )


def _add_provider_edges(
    graph: CapabilityGraph,
    providers: list[dict[str, str]],
    models: list[dict[str, str]],
) -> None:
    for model in models:
        matches = [provider for provider in providers if provider["path"] == model["source_file"]]
        if not matches and len(providers) == 1:
            matches = providers
        for provider in matches:
            graph.add_edge(
                node_id_for(NodeType.MODEL, model["name"]),
                node_id_for(NodeType.PROVIDER, provider["name"]),
                EdgeType.USES,
            )


def _add_reachability_edges(
    graph: CapabilityGraph,
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    prompts: list[dict[str, str]],
    reachable_capabilities: list[dict[str, Any]],
) -> None:
    model_names = {model["name"] for model in models}
    framework_names = {framework["name"] for framework in frameworks}
    prompt_ids = [node_id_for(NodeType.PROMPT, prompt["path"]) for prompt in prompts]

    for reachable in reachable_capabilities:
        actor = str(reachable["reachable_from"])
        capability_id = node_id_for(NodeType.CAPABILITY, str(reachable["capability"]))
        reachable_id = reachable_node_id(reachable)

        if actor in model_names:
            model_id = node_id_for(NodeType.MODEL, actor)
            graph.add_edge(model_id, capability_id, EdgeType.REACHES)
            graph.add_edge(model_id, reachable_id, EdgeType.REACHES)
        if actor in framework_names:
            framework_id = node_id_for(NodeType.FRAMEWORK, actor)
            graph.add_edge(framework_id, capability_id, EdgeType.ENABLES)
            graph.add_edge(framework_id, capability_id, EdgeType.REACHES)
            graph.add_edge(framework_id, reachable_id, EdgeType.REACHES)
        if actor == "prompt configuration":
            for prompt_id in prompt_ids:
                graph.add_edge(prompt_id, capability_id, EdgeType.REACHES)
                graph.add_edge(prompt_id, reachable_id, EdgeType.REACHES)

        server = reachable.get("mcp_server")
        if isinstance(server, str) and server:
            graph.add_edge(
                node_id_for(NodeType.MCP_SERVER, server),
                reachable_id,
                EdgeType.REACHES,
            )
        graph.add_edge(reachable_id, capability_id, EdgeType.REACHES)


def _add_mcp_edges(
    graph: CapabilityGraph,
    mcp_servers: list[dict[str, object]],
) -> None:
    for server in mcp_servers:
        server_id = node_id_for(NodeType.MCP_SERVER, str(server["name"]))
        graph.add_edge(
            server_id,
            node_id_for(NodeType.CAPABILITY, "mcp_tool_invocation"),
            EdgeType.EXPOSES,
        )
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            graph.add_edge(
                server_id,
                node_id_for(NodeType.MCP_RISK, str(category)),
                EdgeType.RISK,
            )


def _parsed_mcp_servers(
    mcp_servers: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [server for server in mcp_servers if server.get("kind") == "server"]
