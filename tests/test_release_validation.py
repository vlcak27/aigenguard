"""Failure cases for the gate that runs before artifact upload/publication."""

import importlib.util
import io
from pathlib import Path
import tarfile
import zipfile

import pytest


spec = importlib.util.spec_from_file_location(
    "verify_release", Path(__file__).resolve().parents[1] / "scripts/verify_release.py",
)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(verify, "ROOT", tmp_path)
    source = tmp_path / "src/aigenguard/__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text('__version__ = "0.8.5"\n')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.8.5"\nrequires-python = ">=3.11"\n'
        '[project.scripts]\naigenguard = "aigenguard.cli:main"\n'
        'agentbom = "aigenguard.cli:main"\n',
    )
    (tmp_path / "README.md").write_text("Release fixture\n")
    (tmp_path / "LICENSE").write_text("MIT\n")
    info = "aigenguard-0.8.5.dist-info/"
    metadata = b"Name: aigenguard\nVersion: 0.8.5\nRequires-Python: >=3.11\n\n"
    wheel_files = {
        "aigenguard/__init__.py": source.read_bytes(),
        info + "METADATA": metadata,
        info + "licenses/LICENSE": b"MIT\n",
        info + "entry_points.txt": (
            b"[console_scripts]\naigenguard = aigenguard.cli:main\nagentbom = aigenguard.cli:main\n"
        ),
    }
    sdist_files = {name: (tmp_path / name).read_bytes()
                   for name in ("src/aigenguard/__init__.py", "pyproject.toml", "README.md", "LICENSE")}
    sdist_files["PKG-INFO"] = metadata
    dist = tmp_path / "dist"
    dist.mkdir()

    def write(wheel_changes=None, sdist_changes=None):
        with zipfile.ZipFile(dist / "aigenguard-0.8.5-py3-none-any.whl", "w") as archive:
            for name, data in (wheel_files | (wheel_changes or {})).items():
                archive.writestr(name, data)
        with tarfile.open(dist / "aigenguard-0.8.5.tar.gz", "w:gz") as archive:
            for name, data in (sdist_files | (sdist_changes or {})).items():
                member = tarfile.TarInfo("aigenguard-0.8.5/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return dist
    return write


def test_release_accepts_matching_artifacts(artifacts):
    wheel, version = verify.verify_archives(artifacts(), "v0.8.5")
    assert wheel.is_file() and version == "0.8.5"


def test_release_rejects_wrong_tag(artifacts):
    with pytest.raises(ValueError, match="tag and package"):
        verify.verify_archives(artifacts(), "v0.8.4")


@pytest.mark.parametrize("changes, message", [
    ({"aigenguard/__init__.py": b"changed"}, "wheel file"),
    ({".env": b"SYNTHETIC=value"}, "unexpected distribution"),
    ({"../outside": b"invalid"}, "unsafe archive"),
    ({"aigenguard-0.8.5.dist-info/entry_points.txt": b"[console_scripts]\n"}, "CLI aliases"),
    ({"aigenguard-0.8.5.dist-info/METADATA": b"Name: wrong\nVersion: 0.8.5\n"}, "invalid metadata"),
])
def test_release_rejects_invalid_wheel(artifacts, changes, message):
    with pytest.raises(ValueError, match=message):
        verify.verify_archives(artifacts(wheel_changes=changes), "v0.8.5")


def test_release_rejects_sdist_source_drift(artifacts):
    with pytest.raises(ValueError, match="sdist source differs"):
        verify.verify_archives(artifacts(sdist_changes={"src/aigenguard/__init__.py": b"drift"}), "v0.8.5")


def test_release_rejects_stale_extra_artifact(artifacts):
    dist = artifacts()
    (dist / "old.whl").touch()
    with pytest.raises(ValueError, match="exactly one wheel"):
        verify.verify_archives(dist, "v0.8.5")
