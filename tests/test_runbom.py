from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import pytest

from aigenguard.cli import main
from aigenguard.policy_paths import MAX_POLICY_FILE_SIZE
from aigenguard.runbom import (
    build_runbom_summary,
    format_runbom_terminal_summary,
    normalize_runbom_event,
)


def test_run_help_explains_direct_commands_without_shell(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["run", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "without a shell" in help_text
    assert "pytest, python" in help_text
    assert "-m pytest, or npm test" in help_text


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversized"])
def test_run_rejects_unsafe_aigenguard_policy_without_traceback(
    tmp_path, monkeypatch, capsys, unsafe_kind
):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
    if unsafe_kind == "symlink":
        outside_policy = tmp_path / "outside.toml"
        outside_policy.write_text("# outside\n", encoding="utf-8")
        policy.symlink_to(outside_policy)
    else:
        policy.write_bytes(b"#" * (MAX_POLICY_FILE_SIZE + 1))
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    assert result == 1
    assert "unsafe repository policy file" in captured.err
    assert "aigenguard.toml" in captured.err
    assert "Traceback" not in captured.err


def test_activate_reuses_existing_policy_and_adds_runbom(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
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
    policy = repo / "aigenguard.toml"
    policy.write_text("# existing policy\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--no-runbom"])

    assert result == 0
    assert policy.read_text(encoding="utf-8") == "# existing policy\n"


def test_activate_preserves_explicit_runbom_command(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--command", "pytest tests/agent_runtime"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "[runbom]" in text
    assert "enabled = true" in text
    assert 'command = "pytest tests/agent_runtime"' in text


def test_activate_autodetects_pytest_when_project_has_pytest_signal(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "tests").mkdir()
    (repo / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "enabled = true" in text
    assert 'command = "python -m pytest"' in text


def test_activate_autodetects_agent_runtime_pytest(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "tests" / "agent_runtime").mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "enabled = true" in text
    assert 'command = "python -m pytest tests/agent_runtime"' in text


def test_activate_autodetects_runbom_pytest(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    (repo / "tests" / "runbom").mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "enabled = true" in text
    assert 'command = "python -m pytest tests/runbom"' in text


def test_activate_writes_disabled_runbom_when_no_command_detected(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert "[runbom]" in text
    assert "enabled = false" in text
    assert 'command = ""' in text


def test_activate_does_not_overwrite_existing_runbom_command_without_force(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[risk]",
                'warn_on = "medium"',
                "",
                "[runbom]",
                "enabled = true",
                'command = "python -m pytest existing_runtime"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "tests" / "agent_runtime").mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    text = policy.read_text(encoding="utf-8")
    assert result == 0
    assert 'command = "python -m pytest existing_runtime"' in text
    assert 'command = "python -m pytest tests/agent_runtime"' not in text


def test_activate_preserves_static_policy_sections_when_adding_runbom(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
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
    assert "AigenGuard RunBOM OK" in captured.out
    assert "Runtime summary:" in captured.out
    assert (repo / "runtime-ok.txt").read_text(encoding="utf-8") == "ok"
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"
    assert events[-1]["exit_code"] == 0
    summary = _read_runbom_summary(repo)
    assert summary["schema_version"] == "runbom.summary.v1"
    assert summary["command"] == command
    assert summary["command_exit_code"] == 0
    assert summary["events_total"] >= 1
    assert summary["unique_events"] >= 1


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
    summary_text = (repo / ".agentbom" / "runbom-summary.json").read_text(encoding="utf-8")
    events = [json.loads(line) for line in log_text.splitlines()]
    assert result == 0
    assert secret not in log_text
    assert secret not in summary_text
    assert any(
        event["event"] == "env.read" and event["name"] == "AGENTBOM_TEST_SECRET"
        for event in events
    )


def test_runbom_success_prints_human_readable_runtime_summary(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    secret = "super-secret-runtime-value"
    (repo / ".env").write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    _write_runbom_config(
        repo,
        _python_command(
            "import os; "
            "from pathlib import Path; "
            "os.getenv('OPENAI_API_KEY'); "
            "Path('.env').read_text(encoding='utf-8')"
        ),
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    summary = _read_runbom_summary(repo)
    assert result == 0
    assert "AigenGuard RunBOM OK" in captured.out
    assert "Runtime summary:" in captured.out
    assert f"{summary['events_total']} events observed" in captured.out
    assert f"{summary['unique_events']} unique events" in captured.out
    assert "Highest risk: high" in captured.out
    assert "Top runtime signals:" in captured.out
    assert "HIGH env.read OPENAI_API_KEY" in captured.out
    assert "Why: agent read an AI provider credential variable name." in captured.out
    assert "Note: secret value was not recorded." in captured.out
    assert "HIGH filesystem.read .env" in captured.out
    assert "Artifacts:" in captured.out
    assert ".agentbom/runbom-summary.json" in captured.out
    assert ".agentbom/runbom.jsonl" in captured.out
    assert secret not in captured.out
    assert secret not in captured.err


def test_runbom_low_only_summary_reports_no_high_or_critical_signals(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, _python_command("open('output.txt', 'w').write('ok')"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    assert result == 0
    assert "Runtime summary:" in captured.out
    assert "Highest risk: low" in captured.out
    assert "No high or critical runtime signals observed." in captured.out


def test_runbom_failed_command_still_prints_summary_when_available(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", "runtime-token-value")
    _write_runbom_config(
        repo,
        _python_command("import os, sys; os.getenv('GITHUB_TOKEN'); sys.exit(7)"),
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    assert result == 7
    assert "AigenGuard RunBOM FAILED" in captured.out
    assert "Runtime command failed with exit code 7" in captured.out
    assert "Runtime summary:" in captured.out
    assert "HIGH env.read GITHUB_TOKEN" in captured.out
    assert "runtime-token-value" not in captured.out
    assert _read_runbom_summary(repo)["command_exit_code"] == 7


def test_runbom_terminal_summary_shows_at_most_five_top_runtime_signals():
    summary = build_runbom_summary(
        [
            {"event": "network.connect", "host": "169.254.169.254", "port": 80},
            {"event": "env.read", "name": "GITHUB_TOKEN"},
            {"event": "env.read", "name": "AWS_ACCESS_KEY_ID"},
            {"event": "env.read", "name": "OPENAI_API_KEY"},
            {"event": "filesystem.read", "path": ".env"},
            {"event": "filesystem.read", "path": ".git/config"},
            {"event": "process.exec", "argv": ["bash", "-lc", "echo ok"]},
        ],
        command_exit_code=0,
        command="python -m pytest",
    )

    output = format_runbom_terminal_summary(summary)

    signal_lines = [
        line for line in output.splitlines() if line.startswith(("  HIGH ", "  CRITICAL "))
    ]
    assert len(signal_lines) == 5
    assert signal_lines[0].startswith("  CRITICAL network.connect 169.254.169.254")


def test_runbom_high_runtime_risk_does_not_fail_successful_command(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "runtime-aws-secret-value")
    _write_runbom_config(
        repo,
        _python_command("import os; os.getenv('AWS_SECRET_ACCESS_KEY')"),
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    assert result == 0
    assert "Highest risk: high" in captured.out
    assert _read_runbom_summary(repo)["command_exit_code"] == 0


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
    assert "AigenGuard RunBOM FAILED" in capsys.readouterr().out
    assert _read_runbom_summary(repo)["command_exit_code"] == 3


def test_runbom_lifecycle_events_still_exist(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    _write_runbom_config(repo, _python_command("print('ok')"))
    monkeypatch.chdir(repo)

    result = main(["run"])

    events = _read_runbom_events(repo)
    assert result == 0
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"


def test_runbom_uses_autodetected_command_when_config_command_is_empty(
    tmp_path, monkeypatch, capsys
):
    repo = _git_repo(tmp_path)
    runtime_tests = repo / "tests" / "agent_runtime"
    runtime_tests.mkdir(parents=True)
    (runtime_tests / "test_runtime.py").write_text("def test_runtime():\n    assert True\n")
    (repo / "aigenguard.toml").write_text(
        "[runbom]\nenabled = true\ncommand = \"\"\n",
        encoding="utf-8",
    )
    python_dir = os.fspath(Path(sys.executable).parent)
    monkeypatch.setenv("PATH", python_dir + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(repo)

    result = main(["run"])

    captured = capsys.readouterr()
    summary = _read_runbom_summary(repo)
    assert result == 0
    assert "RunBOM detected command: python -m pytest tests/agent_runtime" in captured.out
    assert "AigenGuard RunBOM OK" in captured.out
    assert summary["command"] == "python -m pytest tests/agent_runtime"


def test_activate_pre_commit_hook_stays_static_only(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--command", "pytest"])

    hook_text = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert result == 0
    assert "aigenguard guard ." in hook_text
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

    captured = capsys.readouterr()
    summary = _read_runbom_summary(repo)
    assert result == 7
    assert "AigenGuard RunBOM FAILED" in captured.out
    assert "Runtime summary:" in captured.out
    assert summary["command_exit_code"] == 7


def test_runbom_missing_config_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert _setup_message() in capsys.readouterr().err


def test_runbom_disabled_config_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    (repo / "aigenguard.toml").write_text(
        "[runbom]\nenabled = false\ncommand = \"\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert _setup_message() in capsys.readouterr().err


def test_runbom_empty_command_gives_helpful_error(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    (repo / "aigenguard.toml").write_text(
        "[runbom]\nenabled = true\ncommand = \"\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)

    result = main(["run"])

    assert result == 1
    assert _setup_message() in capsys.readouterr().err


@pytest.mark.parametrize(
    ("event", "risk", "tags"),
    [
        (
            {"event": "filesystem.read", "path": ".env"},
            "high",
            {"secret-file", "protected-path"},
        ),
        (
            {"event": "filesystem.read", "path": ".git/config"},
            "high",
            {"git-config", "protected-path"},
        ),
        (
            {"event": "filesystem.write", "path": ".github/workflows/release.yml"},
            "high",
            {"protected-workflow"},
        ),
        (
            {"event": "filesystem.read", "path": "~/.ssh/id_rsa"},
            "critical",
            {"ssh-material", "protected-path"},
        ),
        (
            {"event": "env.read", "name": "GITHUB_TOKEN", "value": "do-not-record"},
            "high",
            {"secret-env", "github-token"},
        ),
        (
            {"event": "env.read", "name": "OPENAI_API_KEY", "value": "do-not-record"},
            "high",
            {"secret-env", "ai-provider-key"},
        ),
        (
            {"event": "env.read", "name": "AWS_ACCESS_KEY_ID"},
            "high",
            {"secret-env", "cloud-credential"},
        ),
        (
            {"event": "process.exec", "argv": ["/bin/bash", "-lc", "echo ok"]},
            "high",
            {"shell-exec"},
        ),
        (
            {"event": "process.exec", "argv": ["curl", "https://example.test"]},
            "high",
            {"network-tool"},
        ),
        (
            {"event": "network.connect", "host": "169.254.169.254", "port": 80},
            "critical",
            {"metadata-service"},
        ),
        (
            {"event": "network.connect", "host": "192.168.1.10", "port": 443},
            "high",
            {"private-network"},
        ),
        (
            {"event": "network.connect", "host": "127.0.0.1", "port": 9},
            "low",
            set(),
        ),
        (
            {"event": "network.connect", "host": "localhost", "port": 9},
            "low",
            set(),
        ),
    ],
)
def test_runbom_normalizes_and_classifies_risky_events(event, risk, tags):
    normalized = normalize_runbom_event(event)

    assert normalized["risk"] == risk
    assert tags.issubset(set(normalized["tags"]))
    assert "do-not-record" not in json.dumps(normalized)


def test_runbom_summary_dedupes_duplicate_env_reads():
    summary = build_runbom_summary(
        [
            {"event": "env.read", "name": "PATH"},
            {"event": "env.read", "name": "PATH"},
            {"event": "env.read", "name": "GITHUB_TOKEN", "value": "do-not-record"},
            {"event": "env.read", "name": "GITHUB_TOKEN", "value": "do-not-record"},
        ],
        command_exit_code=0,
        command="python -m pytest",
    )

    assert summary["events_total"] == 4
    assert summary["unique_events"] == 2
    assert summary["event_types"]["env.read"] == 2
    assert summary["risk_counts"]["low"] == 1
    assert summary["risk_counts"]["high"] == 1
    assert summary["highest_risk"] == "high"
    assert len(summary["risky_events"]) == 1
    assert summary["risky_events"][0]["name"] == "GITHUB_TOKEN"
    assert "do-not-record" not in json.dumps(summary)


def _write_runbom_config(repo, command: str) -> None:
    (repo / "aigenguard.toml").write_text(
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


def _read_runbom_summary(repo) -> dict[str, object]:
    return json.loads((repo / ".agentbom" / "runbom-summary.json").read_text(encoding="utf-8"))


def _setup_message() -> str:
    return "\n".join(
        [
            "RunBOM is not configured yet.",
            "",
            "Run one of:",
            "  aigenguard activate",
            '  aigenguard activate --command "python -m pytest"',
            "",
            "Recommended:",
            "  create tests/agent_runtime/ and run aigenguard activate again",
        ]
    )


def _git_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo
