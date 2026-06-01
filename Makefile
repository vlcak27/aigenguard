.PHONY: install lint test check demo mcp-demo clean

PYTHON ?= python3
AIGENGUARD ?= $(shell if [ -x .venv/bin/aigenguard ]; then printf '.venv/bin/aigenguard'; else printf 'aigenguard'; fi)

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest

check: lint test

demo:
	$(AIGENGUARD) scan examples/research-agent --output-dir aigenguard-report --html --mermaid --sarif --pretty

mcp-demo:
	$(AIGENGUARD) scan examples/mcp-safe-agent --output-dir aigenguard-report/mcp-safe --html --mermaid --sarif --pretty
	$(AIGENGUARD) scan examples/mcp-risky-agent --output-dir aigenguard-report/mcp-risky --html --mermaid --sarif --pretty
	$(AIGENGUARD) scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir aigenguard-report/mcp-policy --html --mermaid --sarif --pretty

clean:
	rm -rf build dist .pytest_cache .ruff_cache aigenguard-report
