"""Compatibility alias for :mod:`aigenguard.cli`."""

import sys
from importlib import import_module

if __name__ == "__main__":
    from aigenguard.cli import main

    raise SystemExit(main())

sys.modules[__name__] = import_module("aigenguard.cli")
