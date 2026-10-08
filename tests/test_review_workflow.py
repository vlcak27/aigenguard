"""Execute maintained PR-workflow blocks against real Git histories."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_review import POLICY, config, git, repo as repository_fixture, stage

repo = repository_fixture
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT/'examples/config-review/github-actions.yml').read_text())
STEPS = {step.get('name'): step for step in WORKFLOW['jobs']['review']['steps']}


def run_step(name, env):
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', STEPS[name]['run']],
                          env=env, cwd=env['RUNNER_TEMP'], capture_output=True, text=True)


@pytest.mark.parametrize('scenario,expected', [('unchanged', 0), ('expanded', 1), ('narrowed', 0),
    ('weakened', 1), ('warnings', 1), ('invalid', 2), ('missing', 2)])
def test_pr_workflow_preserves_report_and_exit(repo, tmp_path, scenario, expected):
    if scenario == 'narrowed':
        stage(repo, config('/'))
    if scenario == 'missing':
        git(repo, 'rm', 'aigenguard.toml')
    if scenario == 'warnings':
        for i in range(40):
            stage(repo, 'import os\nkey = os.getenv("OPENAI_API_KEY")\n', f'client_{i}.py')
    git(repo, 'commit', '--allow-empty', '-qm', 'selected baseline')
    base = git(repo, 'rev-parse', 'HEAD').stdout.strip()
    if scenario in {'expanded', 'weakened', 'warnings'}:
        stage(repo, config('/'))
    elif scenario == 'narrowed':
        stage(repo, config())
    elif scenario == 'invalid':
        stage(repo, '{')
    if scenario == 'weakened':
        stage(repo, POLICY.replace('deny = ["gpt-4o"]', 'deny = []'), 'aigenguard.toml')
        stage(repo, 'from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(model="gpt-4o")\n', 'agent.py')
    git(repo, 'commit', '--allow-empty', '-qm', 'candidate')
    head = git(repo, 'rev-parse', 'HEAD').stdout.strip()
    workspace = tmp_path/'workspace'
    workspace.mkdir()
    for name in ('review-base', 'review-head'):
        git(workspace, 'clone', '--quiet', str(repo), name)
    runtime = tmp_path/'trusted-runtime'
    runtime.mkdir()
    env = dict(os.environ, BASE_SHA=base, HEAD_SHA=head, GITHUB_WORKSPACE=str(workspace),
               RUNNER_TEMP=str(runtime), GITHUB_STEP_SUMMARY=str(runtime/'summary.md'))
    env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env['PATH']
    assert run_step('Prepare Git objects explicitly', env).returncode == 0
    result = run_step('Review Git data with explicit SHAs', env)
    assert result.returncode == expected, result.stdout + result.stderr
    assert run_step('Job summary', env).returncode == 0
    report = json.loads((runtime/'config-review/aigenguard-review.json').read_text())
    summary = (runtime/'summary.md').read_text()
    assert 'Original policy violations' in summary and 'Coverage' in summary
    if scenario == 'weakened':
        assert report['baseline_policy']['violations']
        assert report['policy_changes']
    if scenario == 'warnings':
        assert len(report['baseline_policy']['warnings']) >= 40
        assert len({item['id'] for item in report['baseline_policy']['warnings']}) >= 40
        assert 'further warning(s) in JSON' in summary
        assert summary.index('mcp.filesystem_scope') < summary.index('Original policy warnings')
        assert len(summary) < 12000
    if scenario == 'missing':
        assert 'Establish a trusted baseline' in summary
        assert 'Commit the approved' in summary
