.PHONY: help clean clean-pyc clean-build list test test-all coverage release sdist

UNAME := $(shell uname)

help:
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "release - package and upload a release"
	@echo "sdist - package"

clean: clean-build clean-pyc

clean-build:
	find . -name 'build' -exec rm -rf {} +
	find . -name 'dist' -exec rm -rf {} +
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '.tox' -exec rm -rf {} +
	find . -name '.coverage' -exec rm -rf {} +
	find . -name '.cache' -exec rm -rf {} +
	find . -name '*.deb' -exec rm -rf {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.pytest_cache' -exec rm -rf {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -rf {} +
	find . -name '*.pyo' -exec rm -rf {} +
	find . -name '*~' -exec rm -rf {} +

lint:
	flake8 qa_jobs

test:
	py.test

test-all:
	tox

coverage:
	coverage run --source ape setup.py test
	coverage report -m
	coverage html
	open htmlcov/index.html

release: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

sdist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist
