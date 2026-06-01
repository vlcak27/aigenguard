"""Compatibility alias for :mod:`aigenguard.github_summary`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("aigenguard.github_summary")
