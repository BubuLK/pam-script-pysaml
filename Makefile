.PHONY: help all install-deps test coverage coverage-html lint

help: Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: pytest			## Run pytest

install-deps:		## Install Python requirements.txt
	pip3 install -r requirements.txt

pytest:				## Run pytest
	python3 -m pytest -v

coverage:			## Run pytest with coverage
	python3 -m pytest -v --cov=.

coverage-html:		## Run pytest with coverage (HTML output)
	python3 -m pytest -v --cov=. --cov-report=html

lint:				## Run Flake8/Pylint
	python3 -m flake8
	python3 -m pylint --rcfile=setup.cfg pam_script_pysaml.py