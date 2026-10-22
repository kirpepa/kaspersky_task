.PHONY: run build migrate generate check-generated cert test test-unit test-integration test-db-up vet check coverage docker-up docker-down docker-test

run:
	go run ./cmd/server

build:
	go build -o bin/server ./cmd/server
	go build -o bin/migrate ./cmd/migrate

migrate:
	go run ./cmd/migrate

generate:
	go generate ./internal/transport/http/openapi

cert:
	sh scripts/generate-local-cert.sh

check-generated:
	@set -eu; \
	generated_tmp=$$(mktemp); \
	trap 'rm -f "$$generated_tmp"' EXIT HUP INT TERM; \
	GOTOOLCHAIN=go1.24.4 go tool oapi-codegen -config api/oapi-codegen.yaml -o "$$generated_tmp" api/openapi.yaml; \
	if ! cmp -s internal/transport/http/openapi/api.gen.go "$$generated_tmp"; then \
		echo "Generated API code is out of date. Run make generate."; \
		diff -u internal/transport/http/openapi/api.gen.go "$$generated_tmp" || true; \
		exit 1; \
	fi

test:
	go test -race -count=1 ./...

test-unit:
	go test -race -count=1 ./internal/...

test-integration:
	@test -n "$$TEST_DATABASE_URL" || (echo "Set TEST_DATABASE_URL or use make docker-test"; exit 1)
	go test -race -count=1 ./tests/integration/...

test-db-up:
	docker compose --profile test up -d --wait test-db

vet:
	go vet ./...

check: check-generated vet test

coverage:
	go test -race -count=1 -coverpkg=./internal/... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

docker-up:
	API_UID=$$(id -u) API_GID=$$(id -g) docker compose up --build -d api

docker-down:
	docker compose --profile test down

docker-test:
	docker compose --profile test run --build --rm tests
