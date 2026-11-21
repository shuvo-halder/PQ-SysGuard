.PHONY: help install test lint format run clean

PYTHON ?= python
VENV_DIR ?= .venv

ifeq ($(OS),Windows_NT)
	BIN_DIR = $(VENV_DIR)/Scripts
else
	BIN_DIR = $(VENV_DIR)/bin
endif

VENV_PYTHON = $(BIN_DIR)/python
VENV_PYTEST = $(BIN_DIR)/pytest
VENV_RUFF = $(BIN_DIR)/ruff
VENV_MYPY = $(BIN_DIR)/mypy
VENV_BANDIT = $(BIN_DIR)/bandit

help:
	@echo "PQ-SysGuard Development Targets:"
	@echo "  install  - Install dependencies and package in editable mode"
	@echo "  test     - Run pytest with code coverage"
	@echo "  lint     - Run ruff, mypy, and bandit security scans"
	@echo "  format   - Run ruff formatter and fix safe lint issues"
	@echo "  run      - Run the PQ-SysGuard CLI"
	@echo "  clean    - Remove build artifacts, caches, and temp files"

install:
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -e ".[dev]"

test:
	$(VENV_PYTEST) --cov=src/pqsysguard --cov-report=term-missing tests/

lint:
	$(VENV_RUFF) check src/ tests/
	$(VENV_MYPY) src/ tests/
	$(VENV_BANDIT) -r src/ -c pyproject.toml

format:
	$(VENV_RUFF) format src/ tests/
	$(VENV_RUFF) check --fix src/ tests/

run:
	$(VENV_PYTHON) -m pqsysguard.cli --help

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
