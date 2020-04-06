.PHONY: all install-deps test coverage coverage-html lint

all: test

install-deps:
	pip3 install -r requirements.txt

test:
	python3 -m pytest -v

coverage:
	python3 -m pytest -v --cov=.

coverage-html:
	python3 -m pytest -v --cov=. --cov-report=html

lint:
	python3 -m flake8
	python3 -m pylint pam_script_pysaml.py
