"""Compatibility alias for :mod:`aigenguard.html_report`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("aigenguard.html_report")
