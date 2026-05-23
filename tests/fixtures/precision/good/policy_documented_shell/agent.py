"""A documented local maintenance helper."""

import subprocess


def list_workspace() -> None:
    subprocess.run(["pwd"], check=False)
