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
It is an AI-agent pre-commit review signal about how directly AigenGuard can
tie a finding to local code, structured configuration, credential shape, or
review text. It does not prove that a capability is reachable at runtime,
exploitable, safe, or unsafe.

- high confidence = strong static evidence such as parsed executable code
  evidence, exact tool/API call evidence, a provider-shaped credential value,
  or structured config with a direct risky capability.
- medium confidence = structured config evidence that is indirect, a generic
  secret-like assignment, MCP metadata from parsed config, or risk that needs
  reviewer confirmation.
- low confidence = text-only evidence, docs/prompt wording, an inferred
  cross-file relationship, or a weak or ambiguous static signal.

Severity and confidence are different. Severity describes why the finding may
matter for agent capability, policy context, or security review. Confidence
describes how strong the static evidence is. A high-confidence finding can
still be acceptable if documented by policy, and policy can document risk
without proving safety. A low-confidence finding can still be useful review
context for a reviewer deciding what should be allowed before commit.

These rules keep AigenGuard local-first and AI-agent focused. They also prepare
future Agent Power Delta / Capability Diff work by making current static
evidence consistent before comparing capability changes across commits.
