# GhostCheck Developer Makefile

.PHONY: install test lint clean demo build help

help:
	@echo "Available commands:"
	@echo "  make install  - Install package in editable mode with dev dependencies"
	@echo "  make test     - Run tests with coverage report"
	@echo "  make lint     - Run flake8 and mypy checks"
	@echo "  make clean    - Remove build artifacts and caches"
	@echo "  make demo     - Run the GhostCheck demo scan"
	@echo "  make build    - Build source and wheel distributions"

install:
	pip install -e .[dev]

test:
	pytest tests/ -v --cov=ghostcheck --cov-report=term-missing

lint:
	flake8 src/ tests/
	mypy src/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} +

demo:
	python -m ghostcheck.cli demo
