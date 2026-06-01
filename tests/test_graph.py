from __future__ import annotations

from aigenguard.graph import (
    EdgeType,
    NodeType,
    build_capability_graph,
    build_internal_capability_graph,
    node_id_for,
)


def test_internal_graph_models_prompt_mcp_and_reachable_capability_relationships():
    graph = build_internal_capability_graph(
        providers=[{"name": "openai", "path": "agent.py", "confidence": "high"}],
        models=[
            {
                "type": "model",
                "name": "gpt-4o",
                "source_file": "agent.py",
                "confidence": "high",
                "evidence": "gpt-4o",
            }
        ],
        frameworks=[{"name": "langchain", "path": "agent.py", "confidence": "high"}],
        prompts=[{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}],
        mcp_servers=[
            {
                "name": "filesystem",
                "path": "mcp.json",
                "confidence": "medium",
                "kind": "server",
                "risk": "high",
                "risk_categories": ["filesystem_access"],
            }
        ],
        capabilities=[{"name": "shell", "path": "agent.py", "confidence": "high"}],
        reachable_capabilities=[
            {
                "capability": "code_execution",
                "reachable_from": "gpt-4o",
                "source_file": "agent.py",
                "risk": "high",
                "confidence": "high",
                "paths": ["shell_execution"],
            },
            {
                "capability": "mcp_tool_invocation",
                "reachable_from": "prompt configuration",
                "source_file": "mcp.json",
                "risk": "high",
                "confidence": "low",
                "paths": ["tool_invocation"],
                "mcp_server": "filesystem",
            },
        ],
    )

    serialized = graph.to_dict()

    assert {
        "id": "prompt:AGENTS.md",
        "type": "prompt",
        "name": "AGENTS.md",
    } in serialized["nodes"]
    assert {
        "id": "reachable_capability:gpt-4o:code_execution:agent.py",
        "type": "reachable_capability",
        "name": "gpt-4o -> code_execution",
    } in serialized["nodes"]
    assert {
        "source": "prompt:AGENTS.md",
        "target": "reachable_capability:prompt configuration:mcp_tool_invocation:mcp.json",
        "type": "reaches",
    } in serialized["edges"]
    assert {
        "source": "mcp_server:filesystem",
        "target": "reachable_capability:prompt configuration:mcp_tool_invocation:mcp.json",
        "type": "reaches",
    } in serialized["edges"]


def test_internal_graph_traversal_helpers_are_deterministic():
    graph = build_internal_capability_graph(
        providers=[{"name": "openai", "path": "agent.py", "confidence": "high"}],
        models=[
            {
                "type": "model",
                "name": "gpt-4o",
                "source_file": "agent.py",
                "confidence": "high",
                "evidence": "gpt-4o",
            }
        ],
        frameworks=[],
        prompts=[],
        mcp_servers=[],
        capabilities=[],
        reachable_capabilities=[
            {
                "capability": "network_access",
                "reachable_from": "gpt-4o",
                "source_file": "agent.py",
                "risk": "medium",
                "confidence": "high",
                "paths": ["network_execution"],
            },
            {
                "capability": "code_execution",
                "reachable_from": "gpt-4o",
                "source_file": "agent.py",
                "risk": "high",
                "confidence": "high",
                "paths": ["shell_execution"],
            },
        ],
    )

    model_id = node_id_for(NodeType.MODEL, "gpt-4o")
    successors = graph.successors(model_id, EdgeType.REACHES)
    reachable = graph.reachable_nodes(model_id, edge_types=[EdgeType.REACHES])

    assert [node.id for node in successors] == [
        "capability:code_execution",
        "capability:network_access",
        "reachable_capability:gpt-4o:code_execution:agent.py",
        "reachable_capability:gpt-4o:network_access:agent.py",
    ]
    assert [node.id for node in reachable] == [
        "capability:code_execution",
        "capability:network_access",
        "reachable_capability:gpt-4o:code_execution:agent.py",
        "reachable_capability:gpt-4o:network_access:agent.py",
    ]
    assert [
        node.id
        for node in graph.predecessors(
            node_id_for(NodeType.CAPABILITY, "code_execution"),
            EdgeType.REACHES,
        )
    ] == [
        "model:gpt-4o",
        "reachable_capability:gpt-4o:code_execution:agent.py",
    ]


def test_capability_graph_serialization_is_stable_for_reordered_inputs():
    providers = [{"name": "openai", "path": "agent.py", "confidence": "high"}]
    models = [
        {
            "type": "model",
            "name": "gpt-4o",
            "source_file": "agent.py",
            "confidence": "high",
            "evidence": "gpt-4o",
        }
    ]
    frameworks = [
        {"name": "langchain", "path": "agent.py", "confidence": "high"},
        {"name": "langgraph", "path": "graph.py", "confidence": "high"},
    ]
    capabilities = [
        {"name": "network", "path": "agent.py", "confidence": "high"},
        {"name": "shell", "path": "agent.py", "confidence": "high"},
    ]
    reachable_capabilities = [
        {
            "capability": "network_access",
            "reachable_from": "langchain",
            "source_file": "agent.py",
            "risk": "medium",
            "confidence": "high",
        },
        {
            "capability": "code_execution",
            "reachable_from": "gpt-4o",
            "source_file": "agent.py",
            "risk": "high",
            "confidence": "high",
        },
    ]

    first = build_capability_graph(
        providers,
        models,
        frameworks,
        [],
        capabilities,
        reachable_capabilities,
        [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}],
    )
    second = build_capability_graph(
        list(reversed(providers)),
        list(reversed(models)),
        list(reversed(frameworks)),
        [],
        list(reversed(capabilities)),
        list(reversed(reachable_capabilities)),
        [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}],
    )

    assert first == second
    assert first["nodes"] == sorted(first["nodes"], key=lambda item: (item["type"], item["id"]))
    assert first["edges"] == sorted(
        first["edges"],
        key=lambda item: (item["source"], item["target"], item["type"]),
    )
