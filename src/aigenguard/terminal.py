"""Small terminal styling helpers for human CLI output."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Mapping, TextIO


ANSI_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "bold_red": "1;31",
    "yellow": "33",
    "green": "32",
    "bold_green": "1;32",
    "cyan": "36",
}


@dataclass(frozen=True)
class TerminalStyle:
    enabled: bool

    def apply(self, text: object, style: str) -> str:
        value = str(text)
        if not self.enabled:
            return value
        code = ANSI_CODES[style]
        return f"\033[{code}m{value}\033[0m"

    def bold(self, text: object) -> str:
        return self.apply(text, "bold")

    def dim(self, text: object) -> str:
        return self.apply(text, "dim")

    def red(self, text: object) -> str:
        return self.apply(text, "bold_red")

    def yellow(self, text: object) -> str:
        return self.apply(text, "yellow")

    def green(self, text: object) -> str:
        return self.apply(text, "bold_green")

    def cyan(self, text: object) -> str:
        return self.apply(text, "cyan")


def terminal_style(
    stdout: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    no_color: bool = False,
) -> TerminalStyle:
    stream = sys.stdout if stdout is None else stdout
    env = os.environ if environ is None else environ
    return TerminalStyle(enabled=_supports_color(stream, env, no_color=no_color))


def _supports_color(
    stdout: TextIO,
    environ: Mapping[str, str],
    *,
    no_color: bool = False,
) -> bool:
    if no_color or "NO_COLOR" in environ:
        return False
    return hasattr(stdout, "isatty") and stdout.isatty()


def severity_style(severity: object) -> str | None:
    label = str(severity).lower()
    if label == "critical":
        return "bold_red"
    if label == "high":
        return "yellow"
    if label == "medium":
        return "yellow"
    return None
