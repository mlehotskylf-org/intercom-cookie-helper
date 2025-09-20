SHELL := /bin/bash

.PHONY: run
run:
	go run ./cmd/server

.PHONY: build
build:
	go build -o bin/server ./cmd/server

.PHONY: test
test:
	go test ./... -count=1

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: fmt-strict
fmt-strict:
	gofumpt -l -w .
	gofmt -s -w .

.PHONY: stop
stop:
	@pkill -f "go run ./cmd/server" || echo "Server not running"
	@pkill -f "server" || true
	@sleep 1

.PHONY: restart
restart: stop run

.PHONY: docker
docker:
	docker build -t intercom-cookie-helper:dev .