# PQ-SysGuard Justfile

default:
    @just --list

# Install virtualenv and all dependencies
install:
    python -m venv .venv
    ./.venv/bin/pip install --upgrade pip || ./.venv/Scripts/pip.exe install --upgrade pip
    ./.venv/bin/pip install -e ".[dev]" || ./.venv/Scripts/pip.exe install -e ".[dev]"

# Run tests with coverage
test:
    pytest --cov=src/pqsysguard --cov-report=term-missing tests/

# Run linting and type checking (Ruff, Mypy, Bandit)
lint:
    ruff check src/ tests/
    mypy src/ tests/
    bandit -r src/ -c pyproject.toml

# Format code
format:
    ruff format src/ tests/
    ruff check --fix src/ tests/

# Run the CLI
run:
    python -m pqsysguard.cli --help

# Clean temporary files
clean:
    rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
