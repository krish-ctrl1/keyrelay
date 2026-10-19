GO     ?= go
PYTHON ?= python3
VENV   := sdk/python/.venv

.PHONY: help build certs test test-go test-py venv demo-up demo-calls demo-agent demo-logs demo-down clean

help:
	@echo "build       build binaries into ./bin"
	@echo "test        run Go (race) and Python test suites"
	@echo "demo-up     generate certs and start the Docker Compose demo"
	@echo "demo-calls  run positive/negative calls against the demo"
	@echo "demo-agent  run the LangChain example agent (allowed + denied)"
	@echo "demo-down   stop the demo and remove volumes and certs"

build:
	$(GO) build -o bin/ ./cmd/...

certs:
	@test -f demo/certs/ca.crt || scripts/gen-certs.sh demo/certs

test: test-go test-py

test-go:
	$(GO) vet ./...
	$(GO) test -v -race ./...

$(VENV)/bin/pytest:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -q -e 'sdk/python[test]'

venv: $(VENV)/bin/pytest

test-py: venv
	cd sdk/python && .venv/bin/pytest -v

demo-up: certs
	docker compose up -d --build

demo-calls:
	scripts/demo-calls.sh

demo-agent: venv
	$(VENV)/bin/python sdk/python/examples/langchain_agent.py weather-bot
	$(VENV)/bin/python sdk/python/examples/langchain_agent.py rogue

demo-logs:
	docker compose logs -f keyrelay

demo-down:
	docker compose down -v --remove-orphans
	rm -rf demo/certs

clean: demo-down
	rm -rf bin
