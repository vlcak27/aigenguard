"""Static demo support agent used by AigenGuard documentation.

This file is intentionally not executed by the scanner.
"""

from __future__ import annotations

import os
import sqlite3

from langchain.chat_models import ChatOpenAI
import requests


OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
CRM_BASE_URL = os.environ["CRM_BASE_URL"]


def load_ticket_context(ticket_id: str) -> dict[str, str]:
    with sqlite3.connect("support.db") as connection:
        row = connection.execute(
            "select customer_id, summary from tickets where id = ?",
            (ticket_id,),
        ).fetchone()
    if row is None:
        return {"customer_id": "unknown", "summary": "missing ticket"}
    return {"customer_id": row[0], "summary": row[1]}


def fetch_customer_status(customer_id: str) -> dict[str, object]:
    response = requests.get(
        f"{CRM_BASE_URL}/customers/{customer_id}/status",
        timeout=5,
    )
    return response.json()


def draft_response(ticket_id: str, customer_message: str) -> str:
    ticket = load_ticket_context(ticket_id)
    customer = fetch_customer_status(ticket["customer_id"])
    model = ChatOpenAI(model="gpt-4o", temperature=0)
    prompt = (
        "Draft a concise support reply for human approval. "
        f"Ticket: {ticket['summary']}. "
        f"Customer: {customer}. "
        f"Message: {customer_message}"
    )
    return model.invoke(prompt).content
