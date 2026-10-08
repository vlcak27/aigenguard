"""Execute the actual composite-action shell with the installed scanner."""
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
STEPS = yaml.safe_load((ROOT / 'action.yml').read_text())['runs']['steps']


def shell(step, env, cwd):
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', step['run']],
                          cwd=cwd, env=env, capture_output=True, text=True)


@pytest.mark.parametrize('name', ['normal', 'space here', "apostrophe's", 'double"quote', '$(touch CANARY)', '`touch CANARY`'])
def test_scan_inputs_are_data(tmp_path, name):
    source = tmp_path / name
    source.mkdir()
    (source / 'agent.py').write_text('print("safe")\n')
    output = tmp_path / ('report-' + name)
    env = dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
               INPUT_PATH=str(source), INPUT_OUTPUT_DIR=str(output), INPUT_FAIL_ON='none',
               INPUT_SARIF='false', INPUT_HTML='false', INPUT_CYCLONEDX='false',
               INPUT_POLICY='', INPUT_ENFORCE='false', GITHUB_OUTPUT=str(tmp_path / 'outputs'))
    result = shell(STEPS[1], env, tmp_path)
    assert result.returncode == 0, result.stderr
    assert (output / 'agentbom.json').is_file()
    values = dict(line.split('=', 1) for line in (tmp_path / 'outputs').read_text().splitlines())
    assert values['exit-code'] == '0'
    assert not (tmp_path / 'CANARY').exists()
    env.update(SCAN_STATUS=values['exit-code'], SEVERITY=values['risk-severity'], FAIL_ON='none')
    assert shell(STEPS[-1], env, tmp_path).returncode == 0
    env['FAIL_ON'] = 'low'
    assert shell(STEPS[-1], env, tmp_path).returncode == 1


@pytest.mark.parametrize('key', ['INPUT_FAIL_ON', 'INPUT_SARIF', 'INPUT_HTML', 'INPUT_CYCLONEDX', 'INPUT_ENFORCE'])
def test_invalid_enum_does_not_execute(tmp_path, key):
    env = dict(os.environ, INPUT_FAIL_ON='none', INPUT_SARIF='false', INPUT_HTML='false',
               INPUT_CYCLONEDX='false', INPUT_ENFORCE='false')
    env[key] = '$(touch CANARY)'
    assert shell(STEPS[1], env, tmp_path).returncode == 2
    assert not (tmp_path / 'CANARY').exists()


@pytest.mark.parametrize('code', ['1', '2'])
def test_scan_failure_survives_deferred_threshold(tmp_path, code):
    env = dict(os.environ, SCAN_STATUS=code, SEVERITY='low', FAIL_ON='none')
    assert shell(STEPS[-1], env, tmp_path).returncode == int(code)
