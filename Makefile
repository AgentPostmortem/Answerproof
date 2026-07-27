.PHONY: install lint test demo all

install:
	pip install -e ".[dev]"

lint:
	ruff check .

test:
	pytest -q

demo:
	python examples/demo_rag.py
	python examples/inclusion_proof.py

all: lint test demo
