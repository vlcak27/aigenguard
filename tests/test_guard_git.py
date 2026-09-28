"""Exercise the installed hook through real Git commits, not a mocked index."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from aigenguard.cli import main
from aigenguard.local_guard import install_hook, local_guard_status


SECRET = "sk-proj-GUARDREGRESSION0000000000000000000001"
SAFE_POLICY = "[secrets]\nblock_leaks = true\nwarn_on_detected = false\n"


def git(repo, *args, check=True, input=None):
    # Git's index-info protocol requires LF even on Windows.
    result = subprocess.run(
        ["git", "-C", str(repo), *args], input=input.encode("utf-8") if input else None,
        capture_output=True, check=check,
    )
    return subprocess.CompletedProcess(
        result.args, result.returncode,
        result.stdout.decode("utf-8").replace("\r\n", "\n"),
        result.stderr.decode("utf-8").replace("\r\n", "\n"),
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("GIT_") and key not in {"GIT_EXEC_PATH"}:
            monkeypatch.delenv(key)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.delenv("AIGENGUARD_SKIP_HOOK", raising=False)
    monkeypatch.delenv("AGENTBOM_SKIP_HOOK", raising=False)
    path = tmp_path / "repo with spaces"
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.name", "Guard Test")
    git(path, "config", "user.email", "guard@example.invalid")
    git(path, "config", "commit.gpgSign", "false")
    git(path, "config", "core.autocrlf", "false")
    (path / "aigenguard.toml").write_text(SAFE_POLICY, encoding="utf-8")
    (path / "agent.py").write_text("print('safe')\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-qm", "baseline")
    return path


def install(repo, **kwargs):
    command = shutil.which("aigenguard")
    assert command, "Install the project before running Git integration tests"
    return install_hook(
        "aigenguard.toml", "enforce", cwd=repo,
        aigenguard_command=Path(command).as_posix(), **kwargs,
    )


def commit(repo, *, allowed):
    before = git(repo, "rev-parse", "HEAD").stdout.strip()
    result = git(repo, "commit", "--allow-empty", "-m", "guard regression", check=False)
    after = git(repo, "rev-parse", "HEAD").stdout.strip()
    output = result.stdout + result.stderr
    assert SECRET not in output
    assert (result.returncode == 0) is allowed, output
    assert (after != before) is allowed
    assert "aigenguard" in output.lower(), output
    return output


def test_commit_blocks_staged_secret_hidden_by_working_copy(repo):
    install(repo)
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    git(repo, "add", "agent.py")
    (repo / "agent.py").write_text("print('safe')\n", encoding="utf-8")
    assert "AigenGuard blocked this commit" in commit(repo, allowed=False)


def test_commit_allows_clean_index_with_unstaged_secret(repo):
    install(repo)
    (repo / "agent.py").write_text("print('staged')\n", encoding="utf-8")
    git(repo, "add", "agent.py")
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    commit(repo, allowed=True)
    assert git(repo, "show", "HEAD:agent.py").stdout == "print('staged')\n"


def test_commit_allows_staged_deletion_even_if_working_file_remains(repo):
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    git(repo, "add", "agent.py")
    git(repo, "commit", "-qm", "historical problem")
    install(repo)
    git(repo, "rm", "--cached", "agent.py")
    commit(repo, allowed=True)
    assert git(repo, "cat-file", "-e", "HEAD:agent.py", check=False).returncode != 0


@pytest.mark.parametrize("staged_blocks", [True, False])
def test_commit_uses_staged_policy_not_working_policy(repo, staged_blocks):
    install(repo)
    policy = repo / "aigenguard.toml"
    policy.write_text(SAFE_POLICY.replace("true", str(staged_blocks).lower()), encoding="utf-8")
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    git(repo, "add", "aigenguard.toml", "agent.py")
    policy.write_text(SAFE_POLICY.replace("true", str(not staged_blocks).lower()), encoding="utf-8")
    commit(repo, allowed=not staged_blocks)


def test_commit_uses_index_policy_when_working_policy_is_missing(repo):
    install(repo)
    (repo / "aigenguard.toml").unlink()
    commit(repo, allowed=True)


def test_commit_rejects_deleted_staged_policy(repo):
    install(repo)
    git(repo, "rm", "--cached", "aigenguard.toml")
    commit(repo, allowed=False)


@pytest.mark.parametrize("hooks_path", [".custom-hooks", "absolute"])
def test_custom_hook_path_runs_and_deactivate_preserves_foreign_hook(
    repo, monkeypatch, capsys, hooks_path
):
    hook_dir = repo / "custom hooks" if hooks_path == "absolute" else repo / hooks_path
    git(repo, "config", "core.hooksPath", str(hook_dir) if hooks_path == "absolute" else hooks_path)
    hook_dir.mkdir()
    hook = hook_dir / "pre-commit"
    foreign = "#!/bin/sh\n# keep this spacing   \necho foreign-hook-ran\nexit 0\n\n"
    hook.write_text(foreign, encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    installed = install(repo, append=True)
    assert installed == hook
    status = local_guard_status(cwd=repo)
    assert status.hook_path == hook
    assert status.hook_installed
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    git(repo, "add", "agent.py")
    commit(repo, allowed=False)
    (repo / "agent.py").write_text("print('clean')\n", encoding="utf-8")
    git(repo, "add", "agent.py")
    assert "foreign-hook-ran" in commit(repo, allowed=True)
    monkeypatch.chdir(repo)
    assert main(["status"]) == 0
    assert "Local guard: active" in capsys.readouterr().out
    assert main(["deactivate"]) == 0
    assert not local_guard_status(cwd=repo).hook_installed
    assert hook.read_text(encoding="utf-8") == foreign
    result = git(repo, "commit", "--allow-empty", "-m", "foreign hook retained")
    assert "foreign-hook-ran" in result.stdout + result.stderr
    assert "AigenGuard" not in result.stdout + result.stderr


def test_staged_scan_retains_context_and_original_paths_without_executing_code(repo):
    from aigenguard.scanner import scan_index, scan_path

    (repo / "agent.py").write_text('model = "gpt-4o"\n', encoding="utf-8")
    (repo / "aigenguard.toml").write_text(
        '[capabilities]\ndeny = ["shell_execution"]\n', encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "agent context")
    (repo / "tool.py").write_text(
        "import subprocess\nsubprocess.run('echo executed > executed', shell=True)\n",
        encoding="utf-8",
    )
    git(repo, "add", "tool.py")
    (repo / "agent.py").write_text("print('unstaged')\n", encoding="utf-8")
    (repo / "tool.py").write_text("print('unstaged')\n", encoding="utf-8")
    bom = scan_index(repo, "aigenguard.toml")
    assert bom["repository"] == str(repo)
    assert bom["policy_review"]["policy_file"] == "aigenguard.toml"
    assert any(item["source"] == "tool.py" for item in bom["policy_review"]["violations"])
    assert not (repo / "executed").exists()
    assert not scan_path(repo)["policy_review"]["violations"]
    install(repo)
    assert "blocked this commit" in commit(repo, allowed=False)


def stage_symlink(repo, name, target):
    # Git index mode 120000 is portable, even where OS symlink privileges are absent.
    oid = git(repo, "hash-object", "-w", "--stdin", input=target).stdout.strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},{name}")


def test_staged_symlink_is_not_followed_and_policy_symlink_blocks(repo):
    outside = repo.parent / "outside.py"
    outside.write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    stage_symlink(repo, "linked.py", str(outside))
    install(repo)
    commit(repo, allowed=True)
    stage_symlink(repo, "aigenguard.toml", str(repo / "agent.py"))
    assert "regular file" in commit(repo, allowed=False)


def test_snapshot_does_not_run_git_filters_or_fsmonitor(repo):
    from aigenguard.scanner import scan_index

    (repo / ".gitattributes").write_text("*.py filter=tripwire diff=tripwire\n", encoding="utf-8")
    git(repo, "add", ".gitattributes")
    command = "echo invoked > filter-invoked; cat"
    for setting in ("filter.tripwire.clean", "filter.tripwire.smudge", "diff.tripwire.textconv"):
        git(repo, "config", setting, command)
    git(repo, "config", "core.fsmonitor", "echo invoked > monitor-invoked")
    assert not scan_index(repo, "aigenguard.toml")["policy_review"]["violations"]
    assert not (repo / "filter-invoked").exists()
    assert not (repo / "monitor-invoked").exists()


def test_oversized_staged_policy_blocks(repo):
    install(repo)
    (repo / "aigenguard.toml").write_text("#" * 1_000_001, encoding="utf-8")
    git(repo, "add", "aigenguard.toml")
    (repo / "aigenguard.toml").write_text(SAFE_POLICY, encoding="utf-8")
    assert "1 MB" in commit(repo, allowed=False)


@pytest.mark.parametrize("hooks_path", ["../external-hooks", "absolute"])
def test_external_hooks_path_refused_consistently(repo, monkeypatch, capsys, hooks_path):
    external = repo.parent / "external-hooks"
    external.mkdir()
    hook = external / "pre-commit"
    foreign = "#!/bin/sh\nexit 0\n"
    hook.write_text(foreign, encoding="utf-8")
    git(repo, "config", "core.hooksPath", str(external) if hooks_path == "absolute" else hooks_path)
    monkeypatch.chdir(repo)
    for args in (["activate", "--no-runbom"], ["status"], ["deactivate"]):
        assert main(args) == 1
        output = capsys.readouterr()
        assert "external core.hooksPath" in output.err
        assert "Local guard: active" not in output.out
    assert hook.read_text(encoding="utf-8") == foreign
    assert not (repo / ".git/hooks/pre-commit").exists()


def test_status_uses_new_effective_path_after_config_change(repo):
    install(repo)
    git(repo, "config", "core.hooksPath", ".different-hooks")
    status = local_guard_status(cwd=repo)
    assert not status.hook_installed
    assert status.hook_path == repo / ".different-hooks/pre-commit"


def test_commit_only_uses_the_index_supplied_by_git(repo):
    install(repo)
    (repo / "agent.py").write_text(f'key = "{SECRET}"\n', encoding="utf-8")
    git(repo, "add", "agent.py")
    (repo / "other.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "other.txt")
    result = git(repo, "commit", "--only", "other.txt", "-m", "only safe file")
    assert "AigenGuard OK" in result.stdout + result.stderr
    assert SECRET not in git(repo, "show", "HEAD:agent.py").stdout
    assert SECRET in git(repo, "show", ":agent.py").stdout


def test_activate_default_policy_can_be_committed(repo, monkeypatch):
    monkeypatch.chdir(repo)
    command = Path(shutil.which("aigenguard")).as_posix()
    assert main(["activate", "--force", "--mode", "enforce", "--aigenguard-command", command]) == 0
    git(repo, "add", "aigenguard.toml")
    commit(repo, allowed=True)


def test_intent_to_add_policy_does_not_replace_staged_policy(repo):
    install(repo)
    git(repo, "rm", "--cached", "aigenguard.toml")
    git(repo, "add", "--intent-to-add", "aigenguard.toml")
    assert "policy is missing from the index" in commit(repo, allowed=False)


@pytest.mark.parametrize("name", ["agentbom.toml", "security/custom.toml"])
def test_commit_with_legacy_or_explicit_staged_policy(repo, name):
    policy = repo / name
    policy.parent.mkdir(parents=True, exist_ok=True)
    git(repo, "mv", "aigenguard.toml", name)
    install_hook(
        name, "enforce", cwd=repo,
        aigenguard_command=Path(shutil.which("aigenguard")).as_posix(),
    )
    policy.unlink()
    commit(repo, allowed=True)


def test_snapshot_rejects_unmerged_index(repo):
    from aigenguard.scanner import scan_index

    oid = git(repo, "hash-object", "-w", "--stdin", input="print('safe')\n").stdout.strip()
    git(repo, "update-index", "--index-info", input=(
        f"0 {'0' * len(oid)}\tagent.py\n"
        f"100644 {oid} 1\tagent.py\n100644 {oid} 2\tagent.py\n"
    ))
    with pytest.raises(ValueError, match="cannot verify"):
        scan_index(repo, "aigenguard.toml")


@pytest.mark.skipif(os.name == "nt", reason="Windows does not use POSIX executable mode bits")
def test_status_does_not_claim_non_executable_hook_is_active(repo):
    hook = install(repo)
    hook.chmod(0o644)
    assert not local_guard_status(cwd=repo).hook_installed


def test_symlink_hook_path_refused_without_changing_foreign_hook(repo, make_symlink):
    external = repo.parent / "foreign-hooks"
    external.mkdir()
    hook = external / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    # Use a symlink file so the same capability fixture works on Windows and POSIX.
    make_symlink(repo / ".git/hooks/pre-commit", hook)
    with pytest.raises(ValueError, match="symlink hook"):
        install(repo)
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\nexit 0\n"
