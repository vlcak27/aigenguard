"""Compatibility alias for :mod:`aigenguard.local_guard`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("aigenguard.local_guard")
