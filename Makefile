.PHONY: all install-dev lint test coverage cov test-all tox clean-pyc

all: test

install-dev:
	pip install -q -e .[dev]

lint: clean-pyc
	pylint prs_utility tests

test: clean-pyc install-dev
	pytest

coverage: clean-pyc install-dev
	coverage run -m pytest
	coverage report

test-all: install-dev
	tox

clean-pyc:
	@echo "clean pyc"
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
