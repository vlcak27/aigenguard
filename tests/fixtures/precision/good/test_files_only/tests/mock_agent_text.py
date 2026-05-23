"""Mocked test text mentions subprocess, shell, and OPENAI_API_KEY."""


def test_mocked_security_words_are_text_only() -> None:
    example = "subprocess shell OPENAI_API_KEY"
    assert "OPENAI_API_KEY" in example
