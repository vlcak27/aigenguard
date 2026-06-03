# Static Precision Corpus

The precision corpus is a small set of safe and risky fixture repositories used
to regression-test AigenGuard's static detections.

It exists to keep static findings measurable and to prevent false-positive and
false-negative regressions. See [static precision](../../docs/precision.md) for
scope, limitations, and confidence wording.

Maintainers can run it locally from the repository root:

```sh
python scripts/precision_corpus.py
```

The precision corpus also runs in CI. The CI job makes the corpus visible as a
focused regression suite for static scanner precision.
