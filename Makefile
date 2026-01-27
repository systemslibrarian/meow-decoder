# 🐱 Meow Decoder - Makefile

.PHONY: help install dev test lint format clean build publish \
	formal-proverif formal-proverif-html formal-tla formal-verus formal-all

help:
	@echo "🐱 Meow Decoder - Available Commands:"
	@echo ""
	@echo "  make install     - Install dependencies"
	@echo "  make dev         - Install dev dependencies"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Lint code"
	@echo "  make format      - Format code"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make build       - Build package"
	@echo "  make publish     - Publish to PyPI"
	@echo "  make formal-proverif     - Run ProVerif model"
	@echo "  make formal-proverif-html - ProVerif HTML report"
	@echo "  make formal-tla          - Run TLA+ model"
	@echo "  make formal-verus        - Run Verus proofs"
	@echo "  make formal-all          - Run all formal checks"
	@echo ""
	@echo "🐾 Strong cat passwords only! 😺"

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

test:
	pytest tests/ -v --cov=meow_decoder

lint:
	flake8 meow_decoder/
	black --check meow_decoder/
	mypy meow_decoder/
	bandit -r meow_decoder/ -ll

format:
	black meow_decoder/ tests/

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

build: clean
	python -m build

publish: build
	twine check dist/*
	twine upload dist/*

formal-proverif:
	cd formal/proverif && eval $(opam env) && proverif meow_encode.pv

formal-proverif-html:
	cd formal/proverif && eval $(opam env) && proverif -html output meow_encode.pv

formal-tla:
	cd formal/tla && java -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla

formal-verus:
	cd crypto_core && verus src/lib.rs

formal-all: formal-proverif formal-tla formal-verus

.DEFAULT_GOAL := help
