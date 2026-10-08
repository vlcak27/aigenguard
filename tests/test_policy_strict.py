"""Unknown static keys fail closed through scan, staged guard and review."""
import json
import shutil

import pytest

from aigenguard.cli import main
from aigenguard.local_guard import install_hook
from aigenguard.policy import DEFAULT_TOML_POLICY, PolicyError, normalize_toml_policy
from aigenguard.review import review_repository, review_exit_code
from test_review import git, repo as repository_fixture, stage

repo = repository_fixture


@pytest.mark.parametrize('section', DEFAULT_TOML_POLICY)
def test_unknown_keys_never_echo_names_or_values(section):
    with pytest.raises(PolicyError) as error:
        normalize_toml_policy({section: {'private-canary-name': 'private-canary-value'}})
    assert str(error.value) == f'unsupported key in policy section [{section}]; check documented keys'


def test_runbom_remains_separate():
    assert normalize_toml_policy({'runbom': {'custom_runtime_field': ['example']}}) == normalize_toml_policy({})


def test_unknown_section_does_not_echo_name():
    with pytest.raises(PolicyError, match='unsupported policy section') as error:
        normalize_toml_policy({'private-canary': {}})
    assert 'private-canary' not in str(error.value)


def test_scan_guard_review_reject_typo(repo, tmp_path, capsys):
    invalid = '[models]\ndeny_models=["gpt-4"]\n'
    stage(repo, invalid, 'aigenguard.toml')
    assert main(['scan', str(repo), '--policy', str(repo/'aigenguard.toml'),
                 '--output-dir', str(tmp_path/'reports')]) == 1
    report = review_repository(repo, base='HEAD', staged=True)
    assert review_exit_code(report, 'high') == 2
    assert report['status'] != 'complete'
    install_hook('aigenguard.toml', 'enforce', cwd=repo, aigenguard_command=shutil.which('aigenguard'))
    # Fix only the working copy: the hook must still reject the staged typo.
    (repo/'aigenguard.toml').write_text('[models]\ndeny=["gpt-4"]\n')
    before = git(repo, 'rev-parse', 'HEAD').stdout
    result = git(repo, 'commit', '-qm', 'must fail', check=False)
    assert result.returncode != 0
    assert git(repo, 'rev-parse', 'HEAD').stdout == before
    assert 'unsupported key' in result.stdout + result.stderr
    assert 'deny_models' not in capsys.readouterr().out
    # Invalid baseline must also make review incomplete.
    git(repo, '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'invalid baseline fixture')
    stage(repo, '[models]\ndeny=["gpt-4"]\n', 'aigenguard.toml')
    report = review_repository(repo, base='HEAD', staged=True)
    assert review_exit_code(report) == 2
    assert report['baseline_policy']['status'] == 'not_evaluated'
    assert 'deny_models' not in json.dumps(report)
