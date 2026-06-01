from __future__ import annotations

import io

import pytest

from aigenguard.cli import main
from aigenguard.local_guard import local_guard_status, run_guard
from aigenguard.policy_paths import MAX_POLICY_FILE_SIZE, preferred_policy_path


class TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_install_hook_help_mentions_modes_and_compatibility(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["install-hook", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--mode" in help_text
    assert "advisory warns and allows" in help_text
    assert "confirm asks" in help_text
    assert "enforce blocks" in help_text
    assert "--enforce-policy" in help_text


def test_activate_creates_policy_and_installs_confirm_hook(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    captured = capsys.readouterr()
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert result == 0
    assert (repo / "aigenguard.toml").exists()
    assert hook.exists()
    policy_text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert '"shell_execution"' in policy_text
    assert '"code_execution"' in policy_text
    assert "block_leaks = true" in policy_text
    hook_text = hook.read_text(encoding="utf-8")
    assert '--mode "confirm"' in hook_text
    assert "aigenguard guard ." in hook_text
    assert "aigenguard run" not in hook_text
    assert "runbom" not in hook_text.lower()
    assert "AigenGuard activated" in captured.out
    assert "Policy: aigenguard.toml" in captured.out
    assert "Preset: safe" in captured.out
    assert "Guard mode: confirm" in captured.out
    assert "Protected:" in captured.out
    assert "- AI/API secret leak policy" in captured.out
    assert "- shell/code execution policy" in captured.out
    assert "- MCP server policy" in captured.out
    assert "- risky reachable capability policy" in captured.out
    assert "git commit" in captured.out
    assert "aigenguard status" in captured.out
    assert "aigenguard scan . --policy aigenguard.toml --html --open" in captured.out
    assert not (repo / ".git" / "config").exists()


def test_activate_audit_preset_creates_warn_only_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--preset", "audit"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert result == 0
    assert "Preset: audit" in captured.out
    assert "block_leaks = false" in text
    assert "require_policy_for_risky_servers = false" in text
    assert 'deny = [\n  "shell_execution"' not in text
    assert 'warn_on = "high"' not in text


def test_activate_safe_preset_creates_safe_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--preset", "safe"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert result == 0
    assert "Preset: safe" in captured.out
    assert "warn_on_detected = true" in text
    assert "block_leaks = true" in text
    assert '"shell_execution"' in text
    assert '"code_execution"' in text
    assert "require_policy_for_risky_servers = false" in text


def test_activate_strict_preset_creates_strict_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--preset", "strict"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert result == 0
    assert "Preset: strict" in captured.out
    assert "warn_on_detected = true" in text
    assert "block_leaks = true" in text
    assert '"mcp_tool_invocation"' in text
    assert '"network_access"' in text
    assert "require_policy_for_risky_servers = true" in text


def test_activate_force_overwrites_existing_policy(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
    policy.write_text("# existing policy\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--preset", "strict", "--force"])

    text = policy.read_text(encoding="utf-8")
    assert result == 0
    assert "# existing policy" not in text
    assert '"mcp_tool_invocation"' in text
    assert "block_leaks = true" in text


def test_activate_reuses_legacy_agentbom_policy_as_fallback(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    policy = repo / "agentbom.toml"
    policy.write_text("# legacy policy\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--no-runbom"])

    captured = capsys.readouterr()
    assert result == 0
    assert policy.read_text(encoding="utf-8") == "# legacy policy\n"
    assert not (repo / "aigenguard.toml").exists()
    assert "Policy: agentbom.toml" in captured.out


@pytest.mark.parametrize("name", ["aigenguard.toml", "agentbom.toml"])
def test_preferred_policy_path_rejects_unsafe_existing_symlink(tmp_path, name):
    outside_policy = tmp_path / "outside.toml"
    outside_policy.write_text("# outside\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / name).symlink_to(outside_policy)

    with pytest.raises(ValueError, match="unsafe repository policy file"):
        preferred_policy_path(repo)


def test_activate_fails_for_unsafe_aigenguard_policy_symlink(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    outside_policy = tmp_path / "outside.toml"
    outside_policy.write_text("# outside\n", encoding="utf-8")
    (repo / "aigenguard.toml").symlink_to(outside_policy)
    monkeypatch.chdir(repo)

    result = main(["activate"])

    assert result == 1
    assert outside_policy.read_text(encoding="utf-8") == "# outside\n"
    assert "unsafe repository policy file" in capsys.readouterr().err
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_activate_fails_for_oversized_aigenguard_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    policy = repo / "aigenguard.toml"
    policy.write_bytes(b"#" * (MAX_POLICY_FILE_SIZE + 1))
    monkeypatch.chdir(repo)

    result = main(["activate"])

    assert result == 1
    assert policy.stat().st_size == MAX_POLICY_FILE_SIZE + 1
    assert "unsafe repository policy file" in capsys.readouterr().err
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


@pytest.mark.parametrize("mode", ["advisory", "enforce"])
def test_activate_installs_selected_mode(tmp_path, monkeypatch, mode):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--mode", mode])

    text = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert result == 0
    assert f'--mode "{mode}"' in text


def test_activate_strict_creates_strict_policy_when_missing(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--strict"])

    text = (repo / "aigenguard.toml").read_text(encoding="utf-8")
    assert result == 0
    assert '"shell_execution"' in text
    assert '"code_execution"' in text
    assert '"mcp_tool_invocation"' in text
    assert "require_policy_for_risky_servers = true" in text


def test_activate_strict_rejects_conflicting_preset(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["activate", "--strict", "--preset", "audit"])

    assert result == 1
    assert "--strict cannot be combined" in capsys.readouterr().err
    assert not (repo / "aigenguard.toml").exists()


def test_activate_output_does_not_print_secret_values(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    (repo / "agent.py").write_text("OPENAI_API_KEY = 'do-not-store'\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate"])

    assert result == 0
    captured = capsys.readouterr()
    assert "secret leak policy" in captured.out
    assert "do-not-store" not in captured.out


def test_activate_custom_policy_and_agentbom_command(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(
        [
            "activate",
            "--policy",
            "security/aigenguard.toml",
            "--agentbom-command",
            ".venv/bin/agentbom",
        ]
    )

    hook_text = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert result == 0
    assert (repo / "security" / "aigenguard.toml").exists()
    assert '--policy "security/aigenguard.toml"' in hook_text
    assert ".venv/bin/agentbom guard ." in hook_text


def test_activate_existing_non_aigenguard_hook_fails_by_default(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate"])

    captured = capsys.readouterr()
    assert result == 1
    assert "existing non-AigenGuard pre-commit hook found" in captured.err
    assert "aigenguard install-hook --append --policy aigenguard.toml --mode confirm" in captured.err
    assert "aigenguard activate --append" in captured.err
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho existing\n"
    assert not (repo / "aigenguard.toml").exists()


def test_activate_append_works_with_existing_hook(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--append"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "echo existing" in text
    assert "# BEGIN AigenGuard managed block" in text
    assert '--mode "confirm"' in text


def test_activate_force_overwrites_existing_hook(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["activate", "--force"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "echo existing" not in text
    assert "# BEGIN AigenGuard managed block" in text
    assert '--mode "confirm"' in text


def test_install_hook_append_works_with_existing_hook(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["install-hook", "--append", "--policy", "aigenguard.toml", "--mode", "confirm"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "echo existing" in text
    assert "# BEGIN AigenGuard managed block" in text


def test_status_outside_git_repo_reports_not_detected(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = main(["status"])

    captured = capsys.readouterr()
    assert result == 0
    assert "AigenGuard status" in captured.out
    assert "Repository: not detected" in captured.out
    assert "Local guard: not installed" in captured.out


def test_status_inside_repo_without_guard_suggests_activate(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["status"])

    captured = capsys.readouterr()
    assert result == 0
    assert "Repository: detected" in captured.out
    assert "Policy: missing" in captured.out
    assert "Local guard: not installed" in captured.out
    assert "aigenguard activate" in captured.out


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversized"])
def test_status_rejects_unsafe_aigenguard_policy_without_traceback(
    tmp_path, monkeypatch, capsys, unsafe_kind
):
    repo = _git_repo(tmp_path)
    _write_unsafe_aigenguard_policy(repo, tmp_path, unsafe_kind)
    monkeypatch.chdir(repo)

    result = main(["status"])

    captured = capsys.readouterr()
    assert result == 1
    assert "unsafe repository policy file" in captured.err
    assert "aigenguard.toml" in captured.err
    assert "Traceback" not in captured.err


def test_local_guard_status_honors_explicit_policy_without_managed_hook(tmp_path):
    repo = _git_repo(tmp_path)
    custom_policy = repo / "security" / "custom.toml"
    custom_policy.parent.mkdir()
    custom_policy.write_text("[risk]\n", encoding="utf-8")
    (repo / "aigenguard.toml").write_text("[risk]\n", encoding="utf-8")

    status = local_guard_status(policy_path="security/custom.toml", cwd=repo)

    assert status.policy == "security/custom.toml"
    assert status.policy_exists is True


def test_status_reports_active_guard_and_mode(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)
    assert main(["activate", "--mode", "enforce"]) == 0
    capsys.readouterr()

    result = main(["status"])

    captured = capsys.readouterr()
    assert result == 0
    assert "Repository: detected" in captured.out
    assert "Policy: aigenguard.toml" in captured.out
    assert "Local guard: active" in captured.out
    assert "Mode: enforce" in captured.out
    assert "Hook: .git/hooks/pre-commit" in captured.out


def test_deactivate_removes_hook_block_and_keeps_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)
    assert main(["activate"]) == 0
    capsys.readouterr()

    result = main(["deactivate"])

    captured = capsys.readouterr()
    assert result == 0
    assert "AigenGuard deactivated for this repository." in captured.out
    assert (repo / "aigenguard.toml").exists()
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_deactivate_removes_only_aigenguard_block(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    assert main(["activate", "--append"]) == 0

    result = main(["deactivate"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "echo existing" in text
    assert "# BEGIN AigenGuard managed block" not in text
    assert (repo / "aigenguard.toml").exists()


def test_status_detects_legacy_agentbom_hook_markers(tmp_path):
    repo = _git_repo(tmp_path)
    (repo / "agentbom.toml").write_text("[risk]\n", encoding="utf-8")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(_legacy_agentbom_hook_block(), encoding="utf-8")

    status = local_guard_status(cwd=repo)

    assert status.hook_installed is True
    assert status.policy == "agentbom.toml"
    assert status.mode == "advisory"


def test_install_hook_replaces_legacy_agentbom_hook_markers(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(_legacy_agentbom_hook_block(), encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["install-hook", "--policy", "aigenguard.toml", "--mode", "confirm"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "# BEGIN AgentBOM managed block" not in text
    assert "# BEGIN AigenGuard managed block" in text
    assert '--policy "aigenguard.toml"' in text
    assert '--mode "confirm"' in text


def test_uninstall_hook_removes_legacy_agentbom_hook_markers(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n\n" + _legacy_agentbom_hook_block(), encoding="utf-8")
    monkeypatch.chdir(repo)

    result = main(["uninstall-hook"])

    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert "echo existing" in text
    assert "# BEGIN AgentBOM managed block" not in text


def test_default_install_hook_uses_advisory_mode(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["install-hook", "--policy", "aigenguard.toml"])

    hook = repo / ".git" / "hooks" / "pre-commit"
    text = hook.read_text(encoding="utf-8")
    assert result == 0
    assert hook.exists()
    assert hook.parent == repo / ".git" / "hooks"
    assert '--mode "advisory"' in text
    assert "AIGENGUARD_SKIP_HOOK" in text
    assert "AGENTBOM_SKIP_HOOK" in text
    assert "aigenguard guard . --policy" in text
    assert "--html" not in text
    assert "agentbom.json" not in text
    assert "agentbom.md" not in text
    assert not (repo / ".git" / "config").exists()


@pytest.mark.parametrize(
    ("args", "mode"),
    [
        (["--mode", "confirm"], "confirm"),
        (["--mode", "enforce"], "enforce"),
        (["--enforce-policy"], "enforce"),
    ],
)
def test_install_hook_writes_selected_mode(tmp_path, monkeypatch, args, mode):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    result = main(["install-hook", "--policy", "aigenguard.toml", *args])

    text = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert result == 0
    assert f'--mode "{mode}"' in text


def test_install_hook_rejects_mode_and_enforce_policy(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    monkeypatch.chdir(repo)

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "install-hook",
                "--policy",
                "aigenguard.toml",
                "--mode",
                "confirm",
                "--enforce-policy",
            ]
        )

    assert exc.value.code == 2
    assert "--mode and --enforce-policy cannot be used together" in capsys.readouterr().err


def test_guard_advisory_allows_policy_violations(tmp_path, capsys):
    project, policy = _project_with_model_violation(tmp_path)

    result = main(["guard", str(project), "--policy", str(policy), "--mode", "advisory"])

    captured = capsys.readouterr()
    assert result == 0
    assert "AigenGuard found policy violations" in captured.out
    assert "Commit allowed because guard mode is advisory." in captured.out
    assert not (project / "agentbom.json").exists()
    assert not (project / "agentbom.md").exists()


def test_guard_enforce_blocks_policy_violations(tmp_path, capsys):
    project, policy = _project_with_model_violation(tmp_path)

    result = main(["guard", str(project), "--policy", str(policy), "--mode", "enforce"])

    captured = capsys.readouterr()
    assert result == 1
    assert "AigenGuard blocked this commit" in captured.out
    assert "blocking finding(s)" in captured.out
    assert "Highest severity: medium" in captured.out
    assert "Why:" in captured.out
    assert "Fix:" in captured.out
    assert "AIGENGUARD_SKIP_HOOK=1 git commit" in captured.out
    assert "git commit --no-verify" in captured.out


def test_guard_confirm_allows_on_yes(tmp_path, monkeypatch, capsys):
    project, policy = _project_with_model_violation(tmp_path)
    monkeypatch.setattr("aigenguard.local_guard._read_confirmation_from_tty", lambda prompt: True)

    result = main(["guard", str(project), "--policy", str(policy), "--mode", "confirm"])

    captured = capsys.readouterr()
    assert result == 0
    assert "AigenGuard found policy violations" in captured.out
    assert "Commit allowed." in captured.out


def test_guard_confirm_blocks_on_no(tmp_path, monkeypatch, capsys):
    project, policy = _project_with_model_violation(tmp_path)
    monkeypatch.setattr("aigenguard.local_guard._read_confirmation_from_tty", lambda prompt: False)

    result = main(["guard", str(project), "--policy", str(policy), "--mode", "confirm"])

    captured = capsys.readouterr()
    assert result == 1
    assert "Commit blocked." in captured.out


def test_guard_confirm_fails_closed_without_interactive_tty(tmp_path, monkeypatch, capsys):
    project, policy = _project_with_model_violation(tmp_path)
    monkeypatch.setattr("aigenguard.local_guard._read_confirmation_from_tty", lambda prompt: None)

    result = main(["guard", str(project), "--policy", str(policy), "--mode", "confirm"])

    captured = capsys.readouterr()
    assert result == 1
    assert "aigenguard confirm mode requires an interactive terminal." in captured.out
    assert "Commit blocked. Use advisory mode, enforce mode, or bypass intentionally." in captured.out


def test_guard_prints_ok_plain_when_output_is_not_tty(tmp_path):
    project, policy = _project_without_policy_items(tmp_path)
    out = io.StringIO()

    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO(), environ={})

    assert result == 0
    assert "AigenGuard OK" in out.getvalue()
    assert "No policy violations found." in out.getvalue()
    assert "\033[" not in out.getvalue()


def test_guard_prints_ok_green_when_tty_supports_color(tmp_path):
    project, policy = _project_without_policy_items(tmp_path)
    out = TtyBuffer()

    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO(), environ={})

    assert result == 0
    assert "\033[32mAigenGuard OK\033[0m" in out.getvalue()


def test_guard_no_color_disables_ansi(tmp_path):
    project, policy = _project_without_policy_items(tmp_path)
    out = TtyBuffer()

    result = run_guard(
        project,
        policy,
        "advisory",
        stdout=out,
        stderr=io.StringIO(),
        environ={"NO_COLOR": "1"},
    )

    assert result == 0
    assert "AigenGuard OK" in out.getvalue()
    assert "\033[" not in out.getvalue()


def test_guard_blocking_tty_output_uses_red(tmp_path):
    project, policy = _project_with_model_violation(tmp_path)
    out = TtyBuffer()

    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "\033[31mAigenGuard blocked this commit\033[0m" in output
    assert "\033[33mMEDIUM\033[0m Model denied by policy: gpt-4o." in output


def test_guard_warning_tty_output_uses_yellow(tmp_path):
    project, policy = _project_with_secret_reference_warning(tmp_path)
    out = TtyBuffer()

    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 0
    assert "\033[33mAigenGuard passed with warnings\033[0m" in output
    assert "\033[33mMEDIUM\033[0m Secret reference detected" in output


def test_guard_confirm_tty_output_uses_yellow(tmp_path):
    project, policy = _project_with_model_violation(tmp_path)
    out = TtyBuffer()

    result = run_guard(
        project,
        policy,
        "confirm",
        stdout=out,
        stderr=io.StringIO(),
        environ={},
        confirm_reader=lambda prompt: True,
    )

    output = out.getvalue()
    assert result == 0
    assert "\033[33mAigenGuard found policy violations\033[0m" in output
    assert "Commit allowed." in output


def test_guard_blocking_non_tty_output_has_no_ansi(tmp_path):
    project, policy = _project_with_model_violation(tmp_path)
    out = io.StringIO()

    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "AigenGuard blocked this commit" in output
    assert "\033[" not in output


def test_guard_warnings_do_not_print_secret_values(tmp_path):
    project, policy = _project_with_secret_reference_warning(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO())

    assert result == 0
    assert "AigenGuard passed with warnings" in out.getvalue()
    assert "Secret reference detected" in out.getvalue()
    assert "do-not-store" not in out.getvalue()


def test_guard_enforce_blocks_secret_leaks_with_redacted_output(tmp_path):
    project, policy, secret_value = _project_with_secret_leak(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "AigenGuard blocked this commit" in output
    assert "CRITICAL Possible OpenAI API key value" in output
    assert ".env:1" in output
    assert "Why: likely credential value found in a committed file." in output
    assert "Fix: remove the key, rotate it" in output
    assert "Secret value redacted." in output
    assert secret_value not in output


def test_guard_critical_tty_severity_uses_red(tmp_path):
    project, policy, secret_value = _project_with_secret_leak(tmp_path)
    out = TtyBuffer()

    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "\033[31mCRITICAL\033[0m Possible OpenAI API key value" in output
    assert secret_value not in output


def test_guard_blocked_shell_capability_output_explains_static_evidence(tmp_path):
    project, policy = _project_with_shell_capability_violation(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "HIGH Shell execution capability" in output
    assert "agent.py" in output
    assert "static evidence shows the agent appears capable of executing shell commands" in output
    assert "remove shell access or document and allow it explicitly in aigenguard.toml" in output


def test_guard_blocked_mcp_exposure_output_explains_policy_fix(tmp_path):
    project, policy = _project_with_mcp_exposure_violation(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    assert result == 1
    assert "HIGH MCP filesystem server exposure" in output
    assert ".cursor/mcp.json" in output
    assert "MCP config appears to expose filesystem access." in output
    assert "restrict allowed MCP servers or document the exception in aigenguard.toml" in output


def test_guard_secret_reference_output_does_not_call_reference_a_leak(tmp_path):
    project, policy = _project_with_secret_reference_warning(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO())

    output = out.getvalue()
    assert result == 0
    assert "Secret reference detected" in output
    assert "credential variable name" in output
    assert "not necessarily a leaked secret value" in output
    assert "Secret value redacted." not in output


def test_guard_policy_gap_output_is_review_signal_not_vulnerability(tmp_path):
    project, policy = _project_with_policy_gap_warning(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "advisory", stdout=out, stderr=io.StringIO())

    output = out.getvalue()
    assert result == 0
    assert "Policy gap" in output
    assert "policy finding and review signal" in output
    assert "vulnerability" not in output.lower()


def test_guard_blocked_output_truncates_to_top_five_findings(tmp_path):
    project, policy = _project_with_many_model_violations(tmp_path)

    out = io.StringIO()
    result = run_guard(project, policy, "enforce", stdout=out, stderr=io.StringIO(), environ={})

    output = out.getvalue()
    finding_lines = [
        line for line in output.splitlines() if line.startswith("MEDIUM Model denied by policy")
    ]
    assert result == 1
    assert "7 blocking finding(s)" in output
    assert len(finding_lines) == 5
    assert "Showing top 5 blocking findings." in output
    assert "Run: aigenguard scan . --policy aigenguard.toml --pretty" in output


def test_guard_blocked_no_color_respects_no_color(tmp_path):
    project, policy = _project_with_model_violation(tmp_path)
    out = TtyBuffer()

    result = run_guard(
        project,
        policy,
        "enforce",
        stdout=out,
        stderr=io.StringIO(),
        environ={"NO_COLOR": "1"},
    )

    output = out.getvalue()
    assert result == 1
    assert "AigenGuard blocked this commit" in output
    assert "\033[" not in output


def _git_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


def _legacy_agentbom_hook_block() -> str:
    return "\n".join(
        [
            "# BEGIN AgentBOM managed block",
            'aigenguard guard . --policy "agentbom.toml" --mode "advisory"',
            "# END AgentBOM managed block",
            "",
        ]
    )


def _project_with_model_violation(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("model = 'gpt-4o'\n", encoding="utf-8")
    policy = project / "aigenguard.toml"
    policy.write_text("[models]\ndeny = [\"gpt-4o\"]\n", encoding="utf-8")
    return project, policy


def _project_without_policy_items(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[risk]",
                'warn_on = "critical"',
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _project_with_secret_reference_warning(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("OPENAI_API_KEY = 'do-not-store'\n", encoding="utf-8")
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = true",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _project_with_secret_leak(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    secret_value = "sk-proj-GUARDSECRET0000000000000000000001"
    (project / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")
    policy = project / "aigenguard.toml"
    policy.write_text(
        "[secrets]\nwarn_on_detected = true\nblock_leaks = true\n",
        encoding="utf-8",
    )
    return project, policy, secret_value


def _project_with_shell_capability_violation(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "model = 'gpt-4o'",
                "subprocess.run('echo hello', shell=True)",
            ]
        ),
        encoding="utf-8",
    )
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[capabilities]",
                'deny = ["shell_execution"]',
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _project_with_mcp_exposure_violation(tmp_path):
    project = tmp_path / "agent"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = true",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _project_with_policy_gap_warning(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("agent prompt", encoding="utf-8")
    (project / "agent.py").write_text(
        "import subprocess\nsubprocess.run('echo hello', shell=True)\n",
        encoding="utf-8",
    )
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[policy_gaps]",
                'warn_on = "medium"',
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _project_with_many_model_violations(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    for index in range(6):
        (project / f"agent_{index}.py").write_text(
            f"model = 'gpt-4o'  # model {index}\n",
            encoding="utf-8",
        )
    policy = project / "aigenguard.toml"
    policy.write_text(
        "\n".join(
            [
                "[models]",
                'deny = ["gpt-4o"]',
                "[mcp]",
                "warn_on_unknown_server = false",
                "require_policy_for_risky_servers = false",
                "[secrets]",
                "warn_on_detected = false",
            ]
        ),
        encoding="utf-8",
    )
    return project, policy


def _write_unsafe_aigenguard_policy(repo, tmp_path, unsafe_kind):
    policy = repo / "aigenguard.toml"
    if unsafe_kind == "symlink":
        outside_policy = tmp_path / "outside.toml"
        outside_policy.write_text("# outside\n", encoding="utf-8")
        policy.symlink_to(outside_policy)
        return
    policy.write_bytes(b"#" * (MAX_POLICY_FILE_SIZE + 1))
