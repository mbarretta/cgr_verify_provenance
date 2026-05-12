.PHONY: help check-deps lint typecheck test clean demo-library

PYTHON := python3
SOURCES := verify_provenance.py verify_library.py build_env.py

help:
	@echo "Chainguard Provenance Verification"
	@echo ""
	@echo "Usage:"
	@echo "  make check-deps    Check that required CLI tools are installed"
	@echo "  make lint          Run linter (ruff)"
	@echo "  make typecheck     Run type checker (mypy)"
	@echo "  make test          Run tests"
	@echo "  make demo-library  End-to-end library verification demo"
	@echo "  make clean         Remove generated files"
	@echo ""
	@echo "Running verification:"
	@echo "  ./verify_provenance.py image   --customer-org YOUR_ORG"
	@echo "  ./verify_provenance.py image   --customer-org YOUR_ORG --full"
	@echo "  ./verify_provenance.py library --parent-org YOUR_ORG \\"
	@echo "      --ecosystem java --coordinate org.apache.commons:commons-compress:1.28.0 \\"
	@echo "      --with-signatures"
	@echo "  ./verify_provenance.py build-deps cgr.dev/YOUR_ORG/python:latest"

check-deps:
	@echo "Checking required dependencies..."
	@command -v chainctl >/dev/null 2>&1 || { echo "ERROR: chainctl not found. See PREREQUISITES.md"; exit 1; }
	@command -v crane >/dev/null 2>&1 || { echo "ERROR: crane not found. See PREREQUISITES.md"; exit 1; }
	@command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign not found. See PREREQUISITES.md"; exit 1; }
	@command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }
	@echo "chainctl: $$(chainctl version 2>/dev/null | head -1 || echo 'installed')"
	@echo "crane:    $$(crane version 2>/dev/null || echo 'installed')"
	@echo "cosign:   $$(cosign version 2>/dev/null | head -1 || echo 'installed')"
	@echo "curl:     $$(curl --version 2>/dev/null | head -1 || echo 'installed')"
	@echo ""
	@echo "All required tools installed."

lint:
	@command -v ruff >/dev/null 2>&1 || { echo "Installing ruff..."; pip install ruff; }
	ruff check $(SOURCES)
	ruff format --check $(SOURCES)

format:
	@command -v ruff >/dev/null 2>&1 || { echo "Installing ruff..."; pip install ruff; }
	ruff format $(SOURCES)
	ruff check --fix $(SOURCES)

typecheck:
	@command -v mypy >/dev/null 2>&1 || { echo "Installing mypy..."; pip install mypy; }
	mypy $(SOURCES)

demo-library:
	@echo "Running library verification demo (requires chainctl auth login)..."
	$(PYTHON) verify_provenance.py library \
	  --parent-org barretta \
	  --ecosystem java \
	  --coordinate org.apache.commons:commons-compress:1.28.0 \
	  --with-signatures \
	  --csv-output library-demo.csv

test:
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf __pycache__ .mypy_cache .pytest_cache .ruff_cache
	rm -f *.csv
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
