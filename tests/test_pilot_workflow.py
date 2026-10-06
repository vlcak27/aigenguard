"""Regressions from the wheel/onboarding pilot; no public network needed."""

import importlib.util
from pathlib import Path

import pytest


def test_demo_looks_up_cli_in_python_scripts_directory(monkeypatch, tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts/demo_config_review.py"
    spec = importlib.util.spec_from_file_location("pilot_demo", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scripts = str(tmp_path / "Python" / "Scripts")
    monkeypatch.setattr(module.sysconfig, "get_path", lambda key: scripts if key == "scripts" else None)
    calls = []
    monkeypatch.setattr(module.shutil, "which", lambda executable, path: calls.append((executable, path)))
    with pytest.raises(RuntimeError, match="Install this checkout"):
        module.run_demo(tmp_path / "demo")
    assert calls == [("aigenguard", scripts)]
