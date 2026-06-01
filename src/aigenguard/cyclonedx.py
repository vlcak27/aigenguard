"""CycloneDX export for AigenGuard findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
CYCLONEDX_SPEC_VERSION = "1.5"


def write_cyclonedx_report(
    bom: dict[str, Any], output_dir: str | Path, pretty: bool = False
) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    cyclonedx_path = out / "agentbom.cdx.json"
    indent = 2 if pretty else None
    cyclonedx_path.write_text(
        json.dumps(render_cyclonedx(bom), indent=indent, sort_keys=pretty) + "\n",
        encoding="utf-8",
    )
    return cyclonedx_path


def render_cyclonedx(bom: dict[str, Any]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    _extend_unique(components, _provider_components(bom.get("providers", [])))
    _extend_unique(components, _model_components(bom.get("models", [])))
    _extend_unique(components, _framework_components(bom.get("frameworks", [])))
    _extend_unique(components, _capability_components(bom.get("capabilities", [])))
    _extend_unique(components, _dependency_components(bom.get("dependencies", [])))

    return {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:agentbom-{_slug(str(bom.get('repository', 'repository')))}",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "AigenGuard",
                    "name": "aigenguard",
                    "version": str(bom.get("schema_version", "0.1.0")),
                }
            ],
            "component": {
                "type": "application",
                "name": str(bom.get("repository", "repository")),
                "bom-ref": "agentbom:repository",
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
    }


def _provider_components(items: object) -> list[dict[str, Any]]:
    components = []
    for item in _dicts(items):
        name = str(item.get("name", "provider"))
        components.append(
            _component(
                kind="provider",
                name=name,
                component_type="platform",
                path=str(item.get("path", "")),
                confidence=str(item.get("confidence", "")),
            )
        )
    return components


def _model_components(items: object) -> list[dict[str, Any]]:
    components = []
    for item in _dicts(items):
        name = str(item.get("name", "model"))
        components.append(
            _component(
                kind="model",
                name=name,
                component_type="machine-learning-model",
                path=str(item.get("source_file", "")),
                confidence=str(item.get("confidence", "")),
            )
        )
    return components


def _framework_components(items: object) -> list[dict[str, Any]]:
    components = []
    for item in _dicts(items):
        name = str(item.get("name", "framework"))
        components.append(
            _component(
                kind="framework",
                name=name,
                component_type="framework",
                path=str(item.get("path", "")),
                confidence=str(item.get("confidence", "")),
            )
        )
    return components


def _capability_components(items: object) -> list[dict[str, Any]]:
    components = []
    for item in _dicts(items):
        name = str(item.get("name", "capability"))
        components.append(
            _component(
                kind="capability",
                name=name,
                component_type="data",
                path=str(item.get("path", "")),
                confidence=str(item.get("confidence", "")),
            )
        )
    return components


def _dependency_components(items: object) -> list[dict[str, Any]]:
    components = []
    for item in _dicts(items):
        name = str(item.get("name", "dependency"))
        component = _component(
            kind="dependency",
            name=name,
            component_type="library",
            path=str(item.get("path", "")),
            confidence=str(item.get("confidence", "")),
        )
        component["properties"].append(
            {"name": "agentbom:dependency_category", "value": str(item.get("category", ""))}
        )
        components.append(component)
    return components


def _component(
    kind: str,
    name: str,
    component_type: str,
    path: str,
    confidence: str,
) -> dict[str, Any]:
    return {
        "type": component_type,
        "bom-ref": f"agentbom:{kind}:{_slug(name)}",
        "name": name,
        "properties": [
            {"name": "agentbom:kind", "value": kind},
            {"name": "agentbom:source_file", "value": path},
            {"name": "agentbom:confidence", "value": confidence},
        ],
    }


def _dicts(items: object) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _extend_unique(items: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> None:
    refs = {item["bom-ref"] for item in items}
    for item in new_items:
        if item["bom-ref"] not in refs:
            items.append(item)
            refs.add(item["bom-ref"])


def _slug(value: str) -> str:
    slug = "".join(char.lower() if char.isalnum() else "-" for char in value)
    return "-".join(part for part in slug.split("-") if part)
