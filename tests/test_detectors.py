from __future__ import annotations

import pytest

from aigenguard.detectors import (
    DetectionContext,
    DetectionResult,
    detect_in_file,
    normalize_model_name,
)


class CustomDetector:
    name = "custom"

    def detect(self, context: DetectionContext) -> DetectionResult:
        return DetectionResult(
            {
                "providers": [
                    {"name": "custom", "path": context.relpath, "confidence": "low"}
                ]
            }
        )


def test_detect_in_file_accepts_custom_detectors():
    result = detect_in_file("agent.py", "ignored", (CustomDetector(),))

    assert result.findings == {
        "providers": [{"name": "custom", "path": "agent.py", "confidence": "low"}]
    }


def test_policy_detector_marks_policy_files_without_text():
    result = detect_in_file("SECURITY.md", None)

    assert result.has_policy is True


@pytest.mark.parametrize(
    ("relpath", "text", "provider"),
    [
        ("agent.py", "import ollama\n", "ollama"),
        ("agent.py", 'base_url = "http://localhost:11434"\n', "ollama"),
        ("agent.py", 'api_key = os.environ["DEEPSEEK_API_KEY"]\n', "deepseek"),
        ("agent.py", 'base_url = "https://api.deepseek.com"\n', "deepseek"),
        ("agent.py", 'api_key = os.environ["OPENROUTER_API_KEY"]\n', "openrouter"),
        ("agent.ts", 'baseURL: "https://openrouter.ai/api/v1"\n', "openrouter"),
        ("agent.py", "import google.generativeai as genai\n", "gemini"),
        ("agent.py", "from google import genai\n", "gemini"),
        ("agent.py", "from vertexai.generative_models import GenerativeModel\n", "gemini"),
        ("agent.ts", 'import { GoogleGenAI } from "@google/genai";\n', "gemini"),
        ("agent.ts", 'import { GoogleGenerativeAI } from "@google/generative-ai";\n', "gemini"),
        ("agent.yaml", "api_key: GOOGLE_GENERATIVE_AI_API_KEY\n", "gemini"),
    ],
)
def test_provider_detector_covers_common_sdk_and_env_patterns(relpath, text, provider):
    result = detect_in_file(relpath, text)

    assert {
        "name": provider,
        "path": relpath,
        "confidence": "high" if relpath.endswith((".py", ".ts")) else "medium",
    } in result.findings["providers"]


@pytest.mark.parametrize(
    ("relpath", "text"),
    [
        ("agent.py", "from langgraph.graph import StateGraph\n"),
        ("agent.ts", 'import { StateGraph } from "@langchain/langgraph";\n'),
        ("agent.yaml", "framework: langgraph\n"),
    ],
)
def test_framework_detector_covers_langgraph_patterns(relpath, text):
    result = detect_in_file(relpath, text)

    assert {
        "name": "langgraph",
        "path": relpath,
        "confidence": "high" if relpath.endswith((".py", ".ts")) else "medium",
    } in result.findings["frameworks"]


@pytest.mark.parametrize(
    ("relpath", "text", "framework"),
    [
        ("agent.py", "from pydantic_ai import Agent\n", "pydantic_ai"),
        ("agent.py", "from agents import Agent, Runner\n", "openai_agents"),
        ("agent.ts", 'import { query } from "@anthropic-ai/claude-agent-sdk";\n', "claude_agent_sdk"),
        ("agent.ts", 'import { Agent } from "@mastra/core";\n', "mastra"),
        ("agent.py", "from google.adk.agents import Agent\n", "google_adk"),
        ("agent.py", "from autogen_agentchat.agents import AssistantAgent\n", "ag2"),
        ("agent.ts", 'import { generateText } from "ai";\n', "vercel_ai_sdk"),
        ("agent.py", "from litellm import completion\n", "litellm"),
        ("agent.py", "import instructor\n", "instructor"),
        ("agent.py", "from haystack import Pipeline\n", "haystack"),
        ("agent.py", "import dspy\n", "dspy"),
        ("agent.py", "from langserve import add_routes\n", "langserve"),
    ],
)
def test_framework_detector_covers_new_agent_ecosystems(relpath, text, framework):
    result = detect_in_file(relpath, text)

    assert {
        "name": framework,
        "path": relpath,
        "confidence": "high",
    } in result.findings["frameworks"]


@pytest.mark.parametrize(
    ("relpath", "text", "framework"),
    [
        ("README.md", "from pydantic_ai import Agent\n", "pydantic_ai"),
        ("docs/agent.md", "import dspy\n", "dspy"),
        ("agent.ts", 'import { generateText } from "air";\n', "vercel_ai_sdk"),
    ],
)
def test_framework_detector_avoids_doc_and_near_name_matches(relpath, text, framework):
    result = detect_in_file(relpath, text)

    assert {
        "name": framework,
        "path": relpath,
        "confidence": "low" if relpath.endswith(".md") else "high",
    } not in result.findings.get("frameworks", [])


@pytest.mark.parametrize(
    ("model", "expected_name"),
    [
        ("gpt-4.5-preview", "gpt-4.5-preview"),
        ("gpt-5.1", "gpt-5.1"),
        ("o1-mini", "o1-mini"),
        ("o1", "o1"),
        ("o3", "o3"),
        ("o3-mini", "o3-mini"),
        ("gpt-5.5", "gpt-5.5"),
        ("gpt-5.5-pro", "gpt-5.5-pro"),
        ("gpt-5.4", "gpt-5.4"),
        ("gpt-5.4-pro", "gpt-5.4-pro"),
        ("gpt-5.4-mini", "gpt-5.4-mini"),
        ("gpt-5.4-nano", "gpt-5.4-nano"),
        ("gpt-5", "gpt-5"),
        ("gpt-5-mini", "gpt-5-mini"),
        ("gpt-5-nano", "gpt-5-nano"),
        ("gpt-4.1", "gpt-4.1"),
        ("gpt-4.1-mini", "gpt-4.1-mini"),
        ("gpt-4.1-nano", "gpt-4.1-nano"),
        ("gpt-4o", "gpt-4o"),
        ("gpt-4o-mini", "gpt-4o-mini"),
        ("o4-mini", "o4-mini"),
        ("claude-opus-4", "claude-opus-4"),
        ("claude-opus-4-7", "claude-opus-4.7"),
        ("claude-opus-4.7", "claude-opus-4.7"),
        ("claude-opus-4-6", "claude-opus-4.6"),
        ("claude-opus-4.6", "claude-opus-4.6"),
        ("claude-sonnet-4", "claude-sonnet-4"),
        ("claude-sonnet-4-6", "claude-sonnet-4.6"),
        ("claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("claude-haiku-4", "claude-haiku-4"),
        ("claude-haiku-4-5", "claude-haiku-4.5"),
        ("claude-haiku-4.6", "claude-haiku-4.6"),
        ("claude-3.7-sonnet", "claude-3.7-sonnet"),
        ("claude-3.5-sonnet", "claude-3.5-sonnet"),
        ("claude-3-opus", "claude-3-opus"),
        ("claude-3-haiku", "claude-3-haiku"),
        ("sonnet 4.6", "claude-sonnet-4.6"),
        ("opus 4.6", "claude-opus-4.6"),
        ("haiku 4.6", "claude-haiku-4.6"),
        ("claude sonnet 4.6", "claude-sonnet-4.6"),
        ("claude opus 4.6", "claude-opus-4.6"),
        ("opus4.6", "claude-opus-4.6"),
        ("sonnet4.6", "claude-sonnet-4.6"),
        ("gemini-pro", "gemini-pro"),
        ("gemini-1.5-pro", "gemini-1.5-pro"),
        ("gemini-1.5-flash", "gemini-1.5-flash"),
        ("gemini-2.5-pro", "gemini-2.5-pro"),
        ("gemini-2.5-flash", "gemini-2.5-flash"),
        ("gemini-2.5-flash-lite", "gemini-2.5-flash-lite"),
        ("gemini-2.0-flash", "gemini-2.0-flash"),
        ("gemini-3-pro", "gemini-3-pro"),
        ("gemini-3.1-pro", "gemini-3.1-pro"),
        ("gemini-3.1-flash", "gemini-3.1-flash"),
        ("gemini 3.1 pro", "gemini-3.1-pro"),
        ("Gemini 3.1 Pro", "gemini-3.1-pro"),
        ("deepseek-chat", "deepseek-chat"),
        ("deepseek-reasoner", "deepseek-reasoner"),
        ("deepseek-r1", "deepseek-r1"),
        ("deepseek-v3", "deepseek-v3"),
        ("deepseek-coder", "deepseek-coder"),
        ("llama3", "llama3"),
        ("llama-3.1", "llama-3.1"),
        ("llama3.1", "llama3.1"),
        ("llama3.2", "llama3.2"),
        ("llama3.3", "llama3.3"),
        ("llama4", "llama4"),
        ("llama-3.3-70b", "llama-3.3-70b"),
        ("llama-3.3-70b-instruct", "llama-3.3-70b-instruct"),
        ("codellama", "codellama"),
        ("code-llama", "code-llama"),
        ("qwen2.5", "qwen2.5"),
        ("qwen2.5-coder", "qwen2.5-coder"),
        ("qwen2", "qwen2"),
        ("qwen3", "qwen3"),
        ("qwen2.5-72b-instruct", "qwen2.5-72b-instruct"),
        ("mistral-large", "mistral-large"),
        ("mistral-large-latest", "mistral-large-latest"),
        ("mistral-small", "mistral-small"),
        ("mistral-medium", "mistral-medium"),
        ("codestral", "codestral"),
        ("mixtral-8x7b", "mixtral-8x7b"),
        ("mixtral-8x22b", "mixtral-8x22b"),
        ("grok", "grok"),
        ("grok-2", "grok-2"),
        ("grok-3", "grok-3"),
        ("grok-4", "grok-4"),
        ("command-r", "command-r"),
        ("command-r-plus", "command-r-plus"),
        ("sonar", "sonar"),
        ("sonar-pro", "sonar-pro"),
        ("sonar-reasoning", "sonar-reasoning"),
        ("openai/gpt-5.1", "gpt-5.1"),
        ("anthropic/claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("google/gemini-3.1-pro", "gemini-3.1-pro"),
        ("deepseek/deepseek-r1", "deepseek-r1"),
        ("meta-llama/llama-3.3-70b-instruct", "llama-3.3-70b-instruct"),
        ("mistral/mistral-large", "mistral-large"),
        ("xai/grok-4", "grok-4"),
        ("cohere/command-r-plus", "command-r-plus"),
        ("perplexity/sonar-pro", "sonar-pro"),
        ("qwen/qwen2.5-coder", "qwen2.5-coder"),
        ("openrouter/openai/gpt-5.1", "gpt-5.1"),
        ("openrouter/openai/gpt-5.5", "gpt-5.5"),
        ("openrouter/openai/gpt-5.5-pro", "gpt-5.5-pro"),
        ("openrouter/anthropic/claude-opus-4.7", "claude-opus-4.7"),
        ("openrouter/anthropic/claude-opus-4-7", "claude-opus-4.7"),
        ("openrouter/anthropic/claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("openrouter/deepseek/deepseek-reasoner", "deepseek-reasoner"),
        ("openrouter/google/gemini-3.1-pro", "gemini-3.1-pro"),
        ("openrouter/google/gemini-2.5-pro", "gemini-2.5-pro"),
        ("anthropic/claude-opus-4.7", "claude-opus-4.7"),
        ("openai/gpt-5.5", "gpt-5.5"),
        ("google/gemini-2.5-pro", "gemini-2.5-pro"),
        ("litellm/openai/gpt-5.1", "gpt-5.1"),
        ("litellm/anthropic/claude-sonnet-4.6", "claude-sonnet-4.6"),
    ],
)
def test_model_detector_covers_modern_model_patterns(model, expected_name):
    result = detect_in_file("agent.py", f'model = "{model}"\n')

    assert {
        "type": "model",
        "name": expected_name,
        "source_file": "agent.py",
        "confidence": "high",
        "evidence": model,
    } in result.findings["models"]


@pytest.mark.parametrize(
    "text",
    [
        "the model is professional",
        "this is an opus file",
        "flash message",
        "reasoner function",
        "open model design",
        "sonnet poem",
        "command line",
        "cloud pro plan",
        "sonar as a normal word",
        "grok as a normal verb",
    ],
)
def test_model_detector_avoids_common_word_false_positives(text):
    result = detect_in_file("agent.py", text)

    assert result.findings.get("models", []) == []


def test_model_detector_deduplicates_normalized_model_names():
    result = detect_in_file(
        "agent.py",
        'primary = "openrouter/openai/gpt-5.1"\nfallback = "gpt-5.1"\n',
    )

    assert result.findings["models"] == [
        {
            "type": "model",
            "name": "gpt-5.1",
            "source_file": "agent.py",
            "confidence": "high",
            "evidence": "openrouter/openai/gpt-5.1",
        }
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" sonnet 4.6 ", "claude-sonnet-4.6"),
        ("opus4.6", "claude-opus-4.6"),
        ("haiku_4.6", "claude-haiku-4.6"),
        ("Gemini 3.1 Pro", "gemini-3.1-pro"),
        ("google/gemini 3.1 pro", "gemini-3.1-pro"),
        ("litellm/openai/gpt-5.1", "gpt-5.1"),
        ("openrouter/anthropic/claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("meta-llama/llama-3.3-70b-instruct", "llama-3.3-70b-instruct"),
    ],
)
def test_normalize_model_name(raw, expected):
    assert normalize_model_name(raw) == expected
