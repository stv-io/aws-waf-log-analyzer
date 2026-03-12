.PHONY: help install install-dev test lint format type-check clean build docker-build docker-run publish docs

# Default target
help:
	@echo "AWS WAF Log Analyzer - Development Commands"
	@echo ""
	@echo "Installation:"
	@echo "  install      Install package in development mode"
	@echo "  install-dev  Install package with development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  test         Run tests with coverage"
	@echo "  lint         Run linting (black, ruff)"
	@echo "  format       Format code (black, ruff)"
	@echo "  type-check   Run type checking (mypy)"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  build        Build package for distribution"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run Docker container"
	@echo "  publish      Publish to PyPI"
	@echo ""
	@echo "Utilities:"
	@echo "  clean        Clean build artifacts"
	@echo "  docs         Generate documentation"
	@echo "  config-init  Initialize default configuration"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# Development
test:
	pytest --cov=src/aws_waf_log_analyzer --cov-report=html --cov-report=term-missing

lint:
	black --check src tests
	ruff check src tests

format:
	black src tests
	ruff format src tests

type-check:
	mypy src

# Combined quality check
quality: format lint type-check test
	@echo "All quality checks passed!"

# Build & Deploy
build:
	python -m build

docker-build:
	docker build -t aws-waf-log-analyzer:dev .

docker-run:
	docker run --rm -it aws-waf-log-analyzer:dev --help

publish:
	python -m build
	python -m twine upload dist/*

# Utilities
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docs:
	@echo "Documentation is in README.md and docs/ directory"
	@echo "View README.md for comprehensive documentation"

config-init:
	aws-waf-log-analyzer config init --output waf-analyzer-config.yaml
	@echo "Configuration created: waf-analyzer-config.yaml"

# Development workflow
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify installation"

# Release workflow
release: clean quality build
	@echo "Ready for release!"
	@echo "Run 'make publish' to upload to PyPI"

# Docker development workflow
docker-dev: docker-build docker-run
	@echo "Docker development environment ready!"

# Quick test
quick-test:
	aws-waf-log-analyzer --version
	aws-waf-log-analyzer config init --output test-config.yaml
	aws-waf-log-analyzer config validate test-config.yaml
	rm -f test-config.yaml
	@echo "Quick test passed!"
