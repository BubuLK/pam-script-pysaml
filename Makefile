.PHONY: help all install-deps test coverage coverage-html lint

help: Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: pytest			## Run pytest tests

install-deps:		## Install Debian/Python dependencies
	apt-get install --no-install-recommends zlib1g python3-pip python3-wheel python3-setuptools python3-openssl python3-lxml
	pip3 install -r requirements.txt

install-testing-suite:	## Install Python testing suite dependencies
	pip3 install -r requirements-testing-suite.txt

clean:				## Clean distribution
	rm -rf .coverage htmlcov .pytest_cache __pycache__
	
lint:				## Run Flake8/Pylint code analysis
	python3 -m flake8
	python3 -m pylint --rcfile=setup.cfg pam_script_pysaml.py

pytest:				## Run pytest tests
	python3 -m pytest -v

coverage:			## Run pytest with coverage
	python3 -m pytest -v --cov=. --cov-report=term

coverage-html:		## Run pytest with coverage (HTML output)
	python3 -m pytest -v --cov=. --cov-report=html

pyinstrument:		## Run pyinstrument stack profiler
	python3 -m pyinstrument  tests/run_pam_script.py
