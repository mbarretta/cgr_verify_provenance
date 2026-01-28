.PHONY: help check-deps lint typecheck test clean

PYTHON := python3

help:
	@echo "Chainguard Image Provenance Verification"
	@echo ""
	@echo "Usage:"
	@echo "  make check-deps    Check that required CLI tools are installed"
	@echo "  make lint          Run linter (ruff)"
	@echo "  make typecheck     Run type checker (mypy)"
	@echo "  make test          Run tests"
	@echo "  make clean         Remove generated files"
	@echo ""
	@echo "Running verification:"
	@echo "  ./verify_provenance.py --customer-org YOUR_ORG"
	@echo "  ./verify_provenance.py --customer-org YOUR_ORG --full"

check-deps:
	@echo "Checking required dependencies..."
	@command -v chainctl >/dev/null 2>&1 || { echo "ERROR: chainctl not found. See PREREQUISITES.md"; exit 1; }
	@command -v crane >/dev/null 2>&1 || { echo "ERROR: crane not found. See PREREQUISITES.md"; exit 1; }
	@command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign not found. See PREREQUISITES.md"; exit 1; }
	@echo "chainctl: $$(chainctl version 2>/dev/null | head -1 || echo 'installed')"
	@echo "crane:    $$(crane version 2>/dev/null || echo 'installed')"
	@echo "cosign:   $$(cosign version 2>/dev/null | head -1 || echo 'installed')"
	@echo ""
	@echo "All required tools installed."

lint:
	@command -v ruff >/dev/null 2>&1 || { echo "Installing ruff..."; pip install ruff; }
	ruff check verify_provenance.py
	ruff format --check verify_provenance.py

format:
	@command -v ruff >/dev/null 2>&1 || { echo "Installing ruff..."; pip install ruff; }
	ruff format verify_provenance.py
	ruff check --fix verify_provenance.py

typecheck:
	@command -v mypy >/dev/null 2>&1 || { echo "Installing mypy..."; pip install mypy; }
	mypy verify_provenance.py

test:
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf __pycache__ .mypy_cache .pytest_cache .ruff_cache
	rm -f *.csv
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
