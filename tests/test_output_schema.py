from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentbom.scanner import scan_path


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "output-schema.json"


def test_generated_output_matches_output_schema(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "import requests",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "requests.get('https://example.com')",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    data = scan_path(project)

    validate_schema_subset(data, schema, schema)


def test_output_schema_declares_draft_2020_12():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["type"] == "string"
    assert schema["properties"]["dependencies"]["items"]["$ref"] == "#/$defs/dependency_finding"
    assert schema["properties"]["repository_risk"]["$ref"] == "#/$defs/repository_risk"
    assert schema["properties"]["policy_review"]["$ref"] == "#/$defs/policy_review"


def test_policy_output_matches_output_schema(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("model = 'gpt-4o'\n", encoding="utf-8")
    policy = tmp_path / "agentbom.toml"
    policy.write_text("[models]\ndeny = [\"gpt-4o\"]\n", encoding="utf-8")

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    data = scan_path(project, policy_path=policy)

    validate_schema_subset(data, schema, schema)


def validate_schema_subset(instance: Any, schema: dict[str, Any], root: dict[str, Any]) -> None:
    if "$ref" in schema:
        validate_schema_subset(instance, resolve_ref(schema["$ref"], root), root)
        return

    expected_type = schema.get("type")
    if expected_type == "object":
        assert isinstance(instance, dict)
        for key in schema.get("required", []):
            assert key in instance
        for key, property_schema in schema.get("properties", {}).items():
            if key in instance:
                validate_schema_subset(instance[key], property_schema, root)
    elif expected_type == "array":
        assert isinstance(instance, list)
        item_schema = schema.get("items")
        if item_schema:
            for item in instance:
                validate_schema_subset(item, item_schema, root)
    elif expected_type == "string":
        assert isinstance(instance, str)
    elif expected_type == "integer":
        assert isinstance(instance, int)
    elif expected_type == "boolean":
        assert isinstance(instance, bool)

    if "enum" in schema:
        assert instance in schema["enum"]


def resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    assert ref.startswith("#/")
    value: Any = root
    for part in ref.removeprefix("#/").split("/"):
        value = value[part]
    assert isinstance(value, dict)
    return value
