"""Environment variables are read by name only."""

import os


def api_key_name() -> str | None:
    return os.getenv("OPENAI_API_KEY")
