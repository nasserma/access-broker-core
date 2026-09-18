.PHONY: sync check test coverage lint

sync:
	uv sync --dev

check:
	uv run ruff check .
	uv run pytest -q

test:
	uv run pytest -q --cov=access_broker_core --cov-branch --cov-report=term-missing

lint:
	uv run ruff check .
