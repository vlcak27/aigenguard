# Static Precision Corpus

The precision corpus is a small set of safe and risky fixture repositories used
to regression-test AgentBOM's static detections.

It exists to show that AgentBOM can distinguish harmless AI-agent repository
patterns from concrete risky behavior, and to prevent false-positive and
false-negative regressions.

Run it from the repository root:

```sh
python scripts/precision_corpus.py
```

Good cases are expected to avoid high or critical blocking findings. They cover
documentation-only risky words, environment variable names, placeholders, test
text, and documented policy context.

Bad cases are expected to produce at least one relevant risky signal, such as a
redacted leaked key, shell or code execution, MCP filesystem exposure, unknown
MCP server usage, prompt-authorized shell execution, or a missing policy control.

This is not a scientific benchmark and is not comprehensive. It is a focused
regression and proof-of-value corpus for static scanner precision.
