# Static Precision

AigenGuard uses a static precision regression corpus to keep detector behavior
measurable as the project changes.

The corpus includes:

- good cases that should avoid high or critical blocking findings
- bad cases that should produce a specific risky static signal
- false-positive-focused cases for harmless text, placeholders, and references
- policy-documented cases where policy context should affect review output

The corpus is not comprehensive vulnerability coverage. It is not exploit proof,
and passing it does not prove that a repository is safe. It is a focused
regression suite for whether current static signals stay explainable and stable.

AigenGuard's static scan does not execute scanned code. It does not execute MCP servers.
It does not make network calls during scanning. Findings come from parsed files,
configuration, and text patterns in the local repository.

Precision work should guide detector changes before broadening detection. New
detectors and broader patterns should first explain which corpus case they
improve, which false-positive risk they introduce, and what regression fixture
will hold that boundary.

## Confidence

Confidence means the strength of static evidence, not exploitability.

- high = strong static evidence such as parsed code/config or provider-shaped
  credential values
- medium = structured but indirect evidence
- low = text-only, documentation, prompt, or inferred evidence

For example, a high-confidence finding may still need human review to determine
whether it is exploitable, intentional, or sufficiently controlled by policy.
