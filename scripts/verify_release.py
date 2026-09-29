#!/usr/bin/env python3
"""Validate built artifacts and smoke-test the wheel outside the checkout.

This does not build or publish anything. Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import ast
import configparser
from email.parser import BytesParser
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import tomllib
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SECRET = "sk-proj-RELEASESMOKE00000000000000000000001"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_archives(dist: Path, tag: str) -> tuple[Path, str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    require(not tag or tag == f"v{version}", "tag and package version differ")
    init = ast.parse((ROOT / "src/aigenguard/__init__.py").read_text())
    versions = [
        ast.literal_eval(node.value) for node in init.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
    ]
    require(versions == [version], "source and project version differ")
    wheel = dist / f"aigenguard-{version}-py3-none-any.whl"
    sdist = dist / f"aigenguard-{version}.tar.gz"
    require(set(dist.iterdir()) == {wheel, sdist}, "expected exactly one wheel and one sdist")

    with zipfile.ZipFile(wheel) as archive:
        require(archive.testzip() is None, "wheel CRC check failed")
        wheel_files = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    with tarfile.open(sdist) as archive:
        sdist_files = {}
        for member in archive.getmembers():
            require(member.isfile() or member.isdir(), "sdist contains a link or special file")
            if member.isfile():
                require(member.name.startswith(f"aigenguard-{version}/"), "unexpected sdist root")
                sdist_files[member.name.split("/", 1)[1]] = archive.extractfile(member).read()

    for name in [*wheel_files, *sdist_files]:
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts, "unsafe archive path")
        require(not any(part in {".git", ".venv", "__pycache__"} or part.startswith(".env")
                        for part in path.parts), f"unexpected distribution content: {name}")
        require(not name.endswith(".pyc"), f"unexpected bytecode: {name}")

    metadata_path = f"aigenguard-{version}.dist-info"
    for metadata in [wheel_files[f"{metadata_path}/METADATA"], sdist_files["PKG-INFO"]]:
        parsed = BytesParser().parsebytes(metadata)
        require(parsed["Name"] == "aigenguard" and parsed["Version"] == version, "invalid metadata")
        require(parsed["Requires-Python"] == project["requires-python"], "Python requirement differs")
        require(all("extra ==" in dep for dep in parsed.get_all("Requires-Dist", [])),
                "unexpected runtime dependency")

    entrypoints = configparser.ConfigParser()
    entrypoints.read_string(wheel_files[f"{metadata_path}/entry_points.txt"].decode())
    require(dict(entrypoints["console_scripts"]) == project["scripts"], "CLI aliases differ")
    sources = list((ROOT / "src").rglob("*.py"))
    require({name for name in wheel_files if name.endswith(".py")} ==
            {source.relative_to(ROOT / "src").as_posix() for source in sources},
            "wheel Python module inventory differs from source")
    for source in sources:
        name = source.relative_to(ROOT / "src").as_posix()
        require(wheel_files.get(name) == source.read_bytes(), f"missing or changed wheel file: {name}")
        require(sdist_files.get(f"src/{name}") == source.read_bytes(), f"sdist source differs: {name}")
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        require(sdist_files.get(name) == (ROOT / name).read_bytes(), f"sdist missing or changed: {name}")
    require(any(name.endswith("/LICENSE") for name in wheel_files), "wheel license missing")
    return wheel, version


def smoke_wheel(wheel: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="aigenguard-release-") as directory:
        scratch = Path(directory).resolve()
        require(not scratch.is_relative_to(ROOT), "smoke test must run outside the checkout")
        environment = scratch / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("PYTHON", "GIT_", "PIP_"))
               and key not in {"AIGENGUARD_SKIP_HOOK", "AGENTBOM_SKIP_HOOK", "VIRTUAL_ENV"}}
        env.update(PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, NO_COLOR="1")

        def run(*args: str, cwd: Path = scratch, success: bool = True) -> str:
            result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
            output = result.stdout + result.stderr
            require(SECRET not in output, "smoke secret leaked in output")
            require((result.returncode == 0) == success, f"command failed: {args[0]}\n{output}")
            return output

        run(str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel))
        run(str(python), "-I", "-c", (
            "import aigenguard, agentbom, importlib.metadata, pathlib, sys; "
            "root = pathlib.Path(sys.prefix).resolve(); "
            "assert all(pathlib.Path(m.__file__).resolve().is_relative_to(root) "
            "for m in (aigenguard, agentbom)); "
            "assert aigenguard.__version__ == agentbom.__version__ == "
            f"importlib.metadata.version('aigenguard') == {version!r}"
        ))
        repo = scratch / "repo with spaces"
        repo.mkdir()
        run("git", "init", "-q", str(repo))
        for key, value in (("user.name", "Release Smoke"), ("user.email", "smoke@example.invalid"),
                           ("commit.gpgSign", "false"), ("core.hooksPath", ".hooks")):
            run("git", "config", key, value, cwd=repo)
        (repo / "aigenguard.toml").write_text(
            "[secrets]\nblock_leaks = true\nwarn_on_detected = false\n", encoding="utf-8",
        )
        source = repo / "agent.py"
        safe = "from pathlib import Path\nPath('SCANNED_CODE_EXECUTED').touch()\n"
        source.write_text(safe, encoding="utf-8")
        for alias in ("aigenguard", "agentbom"):
            require(version in run(alias, "--version"), f"wrong {alias} version")
            run(alias, "scan", ".", "--output-dir", str(scratch / alias), cwd=repo)
            require((scratch / alias / "agentbom.json").is_file(), "scan report missing")
        require(not (repo / "SCANNED_CODE_EXECUTED").exists(), "scan executed repository code")
        run("git", "add", "aigenguard.toml", "agent.py", cwd=repo)
        run("aigenguard", "install-hook", "--mode", "enforce", cwd=repo)
        require("Local guard: active" in run("aigenguard", "status", cwd=repo), "hook inactive")
        run("git", "commit", "-qm", "baseline", cwd=repo)
        head = run("git", "rev-parse", "HEAD", cwd=repo)
        source.write_text(f'key = "{SECRET}"\n', encoding="utf-8")
        run("git", "add", "agent.py", cwd=repo)
        source.write_text(safe, encoding="utf-8")
        output = run("git", "commit", "-qm", "must block", cwd=repo, success=False)
        require("AigenGuard blocked this commit" in output, "commit failed for wrong reason")
        require(run("git", "rev-parse", "HEAD", cwd=repo) == head, "blocked commit changed HEAD")
        source.write_text(safe + "# clean staged change\n", encoding="utf-8")
        run("git", "add", "agent.py", cwd=repo)
        source.write_text(f'key = "{SECRET}"\n', encoding="utf-8")
        run("git", "commit", "-qm", "clean index", cwd=repo)
        require(run("git", "rev-parse", "HEAD", cwd=repo) != head, "clean commit did not advance")
        require(not (repo / "SCANNED_CODE_EXECUTED").exists(), "hook executed repository code")
        (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {"files": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
        }}}), encoding="utf-8")
        run("git", "add", ".mcp.json", cwd=repo)
        for alias in ("aigenguard", "agentbom"):
            output = scratch / (alias + "-review")
            run(alias, "review", "--base", "HEAD", "--staged", "--fail-on", "high",
                "--output-dir", str(output), cwd=repo, success=False)
            report = json.loads((output / "aigenguard-review.json").read_text())
            require(report["status"] == "complete", "installed review is incomplete")
            require(any(item["change"] == "added" for item in report["mcp_changes"]),
                    "installed review missed new MCP configuration")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default="", help="require exact v<package-version> for tagged releases")
    args = parser.parse_args()
    wheel, version = verify_archives(args.dist.resolve(), args.tag)
    smoke_wheel(wheel, version)
    print(f"Verified {version}: metadata, archive contents, isolated wheel, both CLIs, scan, Git hook, review.")


if __name__ == "__main__":
    main()
