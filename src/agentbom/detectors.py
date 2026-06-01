"""Compatibility alias for :mod:`aigenguard.detectors`."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("aigenguard.detectors")
