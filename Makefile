.DEFAULT_GOAL := help
PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: help install index api ui lint format typecheck test check clean

help: ## Show available commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Create a virtualenv and install the project with dev tools
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

index: ## Pre-build the target's vector index (otherwise built on first query)
	$(BIN)/python -m ragsentry.target

api: ## Run the API on http://127.0.0.1:8000 with auto-reload
	$(BIN)/uvicorn ragsentry.api.app:create_app --factory --reload

ui: ## Run the dashboard on http://localhost:8501
	$(BIN)/streamlit run src/ragsentry/ui/app.py

lint: ## Lint and check formatting
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format: ## Auto-format and fix lint issues
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

typecheck: ## Static type checking
	$(BIN)/mypy

test: ## Run the test suite with coverage
	$(BIN)/pytest --cov --cov-report=term-missing

check: lint typecheck test ## Everything CI runs

clean: ## Remove caches and the generated index
	rm -rf .data .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
