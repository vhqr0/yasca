# lint

.PHONY: lint
lint: flake8 mypy

.PHONY: mypy
mypy:
	mypy --ignore-missing-imports --check-untyped-defs -m yasca.all

.PHONY: flake8
flake8:
	flake8 yasca

# format

.PHONY: format
format: yapf isort

.PHONY: yapf
yapf:
	yapf -i -r yasca

.PHONY: isort
isort:
	isort yasca
