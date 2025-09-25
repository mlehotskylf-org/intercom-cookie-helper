SHELL := /bin/bash

.PHONY: start
start:
	@if [ -f .env ]; then set -a && source .env && set +a; fi && go run ./cmd/server

.PHONY: start-bg
start-bg:
	@echo "Starting server with logging to server.log..."
	@if [ -f .env ]; then set -a && source .env && set +a; fi && nohup go run ./cmd/server >> server.log 2>&1 &

.PHONY: build
build:
	go build -o bin/server ./cmd/server

.PHONY: test
test:
	# 30s timeout prevents fuzzing tests from being killed by system
	# Current tests run in ~11-12s, so 30s provides good headroom
	# -p=1 runs packages sequentially to avoid parallel execution issues
	go test ./... -count=1 -timeout=30s -p=1

.PHONY: test-security
test-security:
	go test ./internal/security -count=1 -v

.PHONY: test-http
test-http:
	go test ./internal/http -count=1 -v

.PHONY: lint
lint:
	@echo "TODO: Configure golangci-lint"

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: fmt-strict
fmt-strict:
	gofumpt -l -w .
	gofmt -s -w .

.PHONY: stop
stop:
	@echo "Stopping server processes..."
	@pkill -f "go run ./cmd/server" 2>/dev/null || echo "No 'go run ./cmd/server' processes found"
	@if [ -n "$$(lsof -ti:8080 2>/dev/null)" ]; then \
		echo "Killing process on port 8080: $$(lsof -ti:8080)"; \
		kill $$(lsof -ti:8080) 2>/dev/null || true; \
	else \
		echo "No process found on port 8080"; \
	fi
	@sleep 1

.PHONY: restart
restart: stop start-bg
	@echo "Server restarted in background"
	@sleep 2
	@echo "Checking if server started..."
	@if [ -n "$$(lsof -ti:8080 2>/dev/null)" ]; then \
		echo "✓ Server is running on port 8080 (PID: $$(lsof -ti:8080))"; \
	else \
		echo "✗ Server failed to start"; \
	fi

.PHONY: docker
docker:
	docker build -t intercom-cookie-helper:dev .

.PHONY: env-print
env-print:
	go run ./internal/config/cmd/envprint

.PHONY: env-check
env-check:
	go run ./cmd/server -check-config

.PHONY: logs
logs:
	@if [ -f server.log ]; then \
		tail -f server.log; \
	else \
		echo "No server.log file found. Start the server first."; \
	fi

.PHONY: logs-clear
logs-clear:
	@echo "Clearing server logs..."
	@> server.log 2>/dev/null || true
	@echo "Server logs cleared"

.PHONY: logs-tail
logs-tail:
	@if [ -f server.log ]; then \
		tail -n 50 server.log; \
	else \
		echo "No server.log file found."; \
	fi

.PHONY: sanitize
sanitize:
	@if [ -z "$(URL)" ]; then \
		echo "Usage: make sanitize URL=\"https://example.com/path\""; \
		exit 1; \
	fi
	@if [ -f .env ]; then set -a && source .env && set +a; fi && go run ./cmd/server -sanitize "$(URL)"