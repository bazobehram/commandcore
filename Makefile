.PHONY: dev test integration lint format format-check package

dev:
	PYTHONPATH=apps/server python -m commandcore_server.main

test:
	PYTHONPATH=apps/server:agent pytest -q tests

integration:
	PYTHONPATH=apps/server:agent python scripts/integration_smoke.py

lint:
	python -m compileall -q apps/server agent
	ruff check --select F apps agent scripts tests install

format:
	ruff format apps agent scripts tests install

format-check:
	ruff format --check apps agent scripts tests install

package:
	bash scripts/package.sh
