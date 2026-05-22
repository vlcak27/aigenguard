from __future__ import annotations

import json
import shlex
import sys

import pytest

from agentbom.cli import main


def test_run_help_explains_direct_commands_without_shell(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["run", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "without a shell" in help_text
    assert "pytest, python -m pytest, or npm test" in help_text


def test_activate_reuses_existing_policy_and_adds_runbom(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "agentbom.toml"
    policy.write_text("[risk]\nwarn_on = \"medium\"\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate"])

    assert result == 0
    text = policy.read_text(encoding="utf-8")
    assert '[risk]\nwarn_on = "medium"' in text
    assert "[runbom]" in text
    assert "enabled = false" in text


def test_activate_no_runbom_preserves_existing_policy_exactly(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "agentbom.toml"
    policy.write_text("# existing policy\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--no-runbom"])

    assert result == 0
    assert policy.read_text(encoding="utf-8") == "# existing policy\n"


def test_activate_preserves_explicit_runbom_command(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--command", "pytest tests/agent_runtime"])

    text = (repo / "agentbom.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "[runbom]" in text
    assert "enabled = true" in text
    assert 'command = "pytest tests/agent_runtime"' in text


def test_activate_autodetects_pytest(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "tests").mkdir()
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "agentbom.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "enabled = true" in text
    assert 'command = "pytest"' in text


def test_activate_autodetects_agent_runtime_pytest(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "tests" / "agent_runtime").mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "agentbom.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "enabled = true" in text
    assert 'command = "pytest tests/agent_runtime"' in text


def test_activate_preserves_static_policy_sections_when_adding_runbom(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "agentbom.toml"
    policy.write_text(
        "\n".join(
            [
                "[risk]",
                'warn_on = "critical"',
                "",
                "[secrets]",
                "block_leaks = true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)

    result = main(["activate", "--command", "pytest"])

    text = policy.read_text(encoding="utf-8")
    assert result == 0
    assert '[risk]\nwarn_on = "critical"' in text
    assert "[secrets]\nblock_leaks = true" in text
    assert "[runbom]" in text


def test_runbom_runs_configured_command_without_shell_and_writes_jsonl(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    command = _python_command("from pathlib import Path; Path('runtime-ok.txt').write_text('ok')")
    _write_runbom_config(repo, command)
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    events = [
        json.loads(line)
        for line in (repo / ".agentbom" / "runbom.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert result == 0
    assert "AgentBOM RunBOM OK" in captured.out
    assert (repo / "runtime-ok.txt").read_text(encoding="utf-8") == "ok"
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"
    assert events[-1]["exit_code"] == 0


def test_runbom_records_filesystem_read_event(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "input.txt").write_text("hello", encoding="utf-8")
    _write_runbom_config(repo, _python_command("open('input.txt', encoding='utf-8').read()"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert any(
        event["event"] == "filesystem.read" and event["path"] == "input.txt"
        for event in events
    )


def test_runbom_records_filesystem_write_event(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, _python_command("open('output.txt', 'w').write('hello')"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert any(
        event["event"] == "filesystem.write" and event["path"] == "output.txt"
        for event in events
    )


def test_runbom_records_process_exec_event(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    script = (
        "import subprocess, sys; "
        "subprocess.run([sys.executable, '-c', 'print(123)'], check=True)"
    )
    _write_runbom_config(repo, _python_command(script))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert any(
        event["event"] == "process.exec" and "-c" in event["argv"] for event in events
    )


def test_runbom_records_network_connect_event(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    script = """import socket

try:
    socket.create_connection(("127.0.0.1", 9), timeout=0.001)
except OSError:
    pass
"""
    _write_runbom_config(repo, _python_command(script))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert any(
        event["event"] == "network.connect"
        and event["host"] == "127.0.0.1"
        and event["port"] == 9
        for event in events
    )


def test_runbom_records_env_read_event_without_secret_value(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    secret = "super-secret-runtime-value"
    monkeypatch.setenv("AGENTBOM_TEST_SECRET", secret)
    _write_runbom_config(
        repo,
        _python_command("import os; os.getenv('AGENTBOM_TEST_SECRET')"),
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    log_text = (repo / ".agentbom" / "runbom.jsonl").read_text(encoding="utf-8")
    events = [json.loads(line) for line in log_text.splitlines()]
    assert result == 0
    assert secret not in log_text
    assert any(
        event["event"] == "env.read" and event["name"] == "AGENTBOM_TEST_SECRET"
        for event in events
    )


def test_runbom_decodes_bytes_env_read_names(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    secret = "bytes-secret-runtime-value"
    monkeypatch.setenv("AGENTBOM_TEST_SECRET", secret)
    script = (
        "import os; "
        "os.environb.get(b'AGENTBOM_TEST_SECRET') "
        "if hasattr(os, 'environb') else os.getenv('AGENTBOM_TEST_SECRET')"
    )
    _write_runbom_config(repo, _python_command(script))
    monkeypatch.chdir(repo)

    result = main(["run"])

    log_text = (repo / ".agentbom" / "runbom.jsonl").read_text(encoding="utf-8")
    events = [json.loads(line) for line in log_text.splitlines()]
    env_names = [
        event["name"] for event in events if event["event"] == "env.read"
    ]
    assert result == 0
    assert secret not in log_text
    assert "AGENTBOM_TEST_SECRET" in env_names
    assert "b'AGENTBOM_TEST_SECRET'" not in env_names


def test_runbom_preserves_command_exit_code(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, _python_command("import sys; sys.exit(3)"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 3
    assert "AgentBOM RunBOM FAILED" in capsys.readouterr().out


def test_runbom_lifecycle_events_still_exist(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, _python_command("print('ok')"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"


def test_activate_pre_commit_hook_stays_static_only(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--command", "pytest"])

    hook_text = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert result == 0
    assert "agentbom guard ." in hook_text
    assert "agentbom run" not in hook_text
    assert "runbom" not in hook_text.lower()


def test_runbom_rejects_shell_operators(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    command = f"{shlex.quote(sys.executable)} -c \"print('ok')\" && echo shell"
    _write_runbom_config(repo, command)
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert "RunBOM commands are executed without a shell" in capsys.readouterr().err
    assert not (repo / ".agentbom" / "runbom.jsonl").exists()


def test_runbom_unparseable_command_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, "pytest 'unterminated")
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert "RunBOM command could not be parsed" in capsys.readouterr().err


def test_runbom_failing_command_returns_nonzero(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    command = _python_command("import sys; sys.exit(7)")
    _write_runbom_config(repo, command)
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 7
    assert "AgentBOM RunBOM FAILED" in capsys.readouterr().out


def test_runbom_missing_config_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert "RunBOM is not configured. Run: agentbom activate" in capsys.readouterr().err


def test_runbom_disabled_config_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    (repo / "agentbom.toml").write_text(
        "[runbom]\nenabled = false\ncommand = \"\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert (
        'RunBOM is not enabled. Run: agentbom activate --command "pytest"'
        in capsys.readouterr().err
    )


def test_runbom_empty_command_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    (repo / "agentbom.toml").write_text(
        "[runbom]\nenabled = true\ncommand = \"\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert (
        'RunBOM has no runtime command configured. Run: agentbom activate --command "pytest"'
        in capsys.readouterr().err
    )


def _write_runbom_config(repo, command: str) -> None:
    (repo / "agentbom.toml").write_text(
        "\n".join(
            [
                "[runbom]",
                "enabled = true",
                'preset = "safe"',
                f"command = {json.dumps(command)}",
                'baseline = ".agentbom/runbom-baseline.json"',
                'fail_on_new = "high"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def _python_command(script: str) -> str:
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(script)}"


def _read_runbom_events(repo) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (repo / ".agentbom" / "runbom.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def _git_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo
