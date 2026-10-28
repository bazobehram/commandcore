.PHONY: dev test session-security-gate integration lint format format-check package

dev:
	PYTHONPATH=apps/server python -m commandcore_server.main

test:
	PYTHONPATH=apps/server:agent pytest -q tests

session-security-gate:
	PYTHONPATH=apps/server:agent python -m pytest --runxfail -q tests/test_host_session_trust.py

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
