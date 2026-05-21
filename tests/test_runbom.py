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
    command = (
        f"{shlex.quote(sys.executable)} -c "
        "\"from pathlib import Path; Path('runtime-ok.txt').write_text('ok')\""
    )
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
    assert [event["event"] for event in events] == ["run.start", "run.end"]
    assert events[-1]["exit_code"] == 0


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
    command = f"{shlex.quote(sys.executable)} -c \"import sys; sys.exit(7)\""
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


def _git_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo
