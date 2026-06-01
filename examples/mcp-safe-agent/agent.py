"""Static MCP safe-agent demo.

This file is intentionally not executed by AigenGuard.
"""

from __future__ import annotations

import os

from langchain.chat_models import ChatOpenAI


OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]


def draft_from_approved_memory(question: str, memory_note: str) -> str:
    model = ChatOpenAI(model="gpt-4o", temperature=0)
    prompt = (
        "Use only approved local memory notes. "
        "Human approval is required before sending. "
        f"Question: {question}. Note: {memory_note}"
    )
    return model.invoke(prompt).content
