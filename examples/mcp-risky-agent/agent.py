"""Static MCP risky-agent demo.

This file is intentionally not executed by AigenGuard.
"""

from __future__ import annotations

import os

from langgraph.graph import StateGraph
from openai import OpenAI


OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]


def build_research_graph() -> StateGraph:
    graph = StateGraph(dict)
    return graph


def draft_research_plan(topic: str) -> str:
    client = OpenAI(api_key=OPENAI_API_KEY)
    model = "gpt-4o"
    return client.responses.create(
        model=model,
        input=f"Plan MCP-assisted research for: {topic}",
    ).output_text
