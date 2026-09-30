"""Shared recognizable-credential display redaction, not arbitrary-secret detection.

Patterns moved from the static guard; digests used elsewhere are comparison
metadata, not anonymization. Never use display strings as internal identities.
"""

import re


STATIC_SECRET_VALUE_RE = re.compile("|".join([
    r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}",
    r"sk-ant-[A-Za-z0-9_-]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"AIza[0-9A-Za-z_-]{20,}",
    r"hf_[A-Za-z0-9]{20,}",
]), re.IGNORECASE)


def redact_text(value: str) -> str:
    return STATIC_SECRET_VALUE_RE.sub("[REDACTED]", value)


def redact_data(value):
    """Sanitize the complete display model before any exporter receives it."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        return {redact_text(key): redact_data(item) for key, item in value.items()}
    return value
