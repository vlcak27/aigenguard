import json
import shlex
import sys

import pytest

from aigenguard.runbom import run_runbom


@pytest.mark.parametrize("api", ["run", "Popen"])
@pytest.mark.parametrize("case", ["password", "token", "bearer", "url", "provider"])
def test_instrumentation_never_writes_sensitive_arguments(tmp_path, capsys, api, case):
    canaries = [
        "V4lueCanary987654p", "V4lueCanary987654t", "V4lueCanary987654b",
        "V4lueCanary987654u", "V4lueCanary987654w",
        "sk-proj-CANARYONLY000000000000000000000001",
    ]
    arguments = {
        "password": ["--password", canaries[0]],
        "token": ["--token=" + canaries[1]],
        "bearer": ["Authorization: Bearer " + canaries[2]],
        "url": [f"https://{canaries[3]}:{canaries[4]}@example.invalid/"],
        "provider": [canaries[5]],
    }[case]
    script = (
        "import subprocess, sys\nfrom pathlib import Path\n"
        f"args = [sys.executable, '-c', 'pass'] + {arguments!r}\n"
        + ("subprocess.run(args, check=True)\n" if api == "run"
           else "assert subprocess.Popen(args).wait() == 0\n")
        + "Path('first-write.jsonl').write_bytes(Path('.agentbom/runbom.jsonl').read_bytes())\n"
    )
    (tmp_path / "probe.py").write_text(script, encoding="utf-8")
    # Exercise both lifecycle command storage and the instrumented child process.
    command = shlex.join([sys.executable, "probe.py", *arguments])
    config = tmp_path / "aigenguard.toml"
    config.write_text('[runbom]\nenabled = true\ncommand = ' + json.dumps(command), encoding="utf-8")
    assert run_runbom(config) == 0
    terminal = capsys.readouterr()
    for path in (
        tmp_path / "first-write.jsonl", tmp_path / ".agentbom/runbom.jsonl",
        tmp_path / ".agentbom/runbom-summary.json",
    ):
        text = path.read_text(encoding="utf-8")
        assert all(canary not in text for canary in canaries), path.name
    assert all(canary not in terminal.out + terminal.err for canary in canaries)
    raw_events = [json.loads(line) for line in (tmp_path / "first-write.jsonl").read_text().splitlines()]
    assert any(event["event"] == "process.exec" for event in raw_events)
