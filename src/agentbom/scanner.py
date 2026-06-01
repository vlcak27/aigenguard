"""Compatibility alias for :mod:`aigenguard.scanner`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("aigenguard.scanner")
