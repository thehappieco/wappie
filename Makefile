.PHONY: help run test test-race lint lint-layout vet fmt cover fuzz dev-up dev-down build tidy check \
	client-install client-build client-test client-check public-source

GO      ?= go
PKGS    := ./...
BIN     := bin

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build all binaries
	$(GO) build -o $(BIN)/ ./cmd/...

run: build ## Build and run the server (reads .env)
	./$(BIN)/whatserverd

test: ## Run tests
	$(GO) test $(PKGS)

test-race: ## Run tests with the race detector
	$(GO) test -race $(PKGS)

cover: ## Report coverage
	$(GO) test -race -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1

fuzz: ## Short fuzz pass over every fuzz target
	@for p in $$($(GO) list $(PKGS)); do \
	  for f in $$($(GO) test -list='Fuzz.*' $$p 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "--- $$p $$f"; \
	    $(GO) test -run=NONE -fuzz=$$f -fuzztime=10s $$p || exit 1; \
	  done; \
	done

vet: ## go vet
	$(GO) vet $(PKGS)

fmt: ## Check formatting
	@out=$$(gofmt -l cmd internal);  \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

# The whatsapp_server2 project rotted because a half-finished migration left
# API_ttt/ and mongo_ttt/ beside the real packages and nobody ever removed
# them. Fail the build rather than let that start.
lint-layout: ## Reject parallel legacy package copies
	@bad=$$(find . -type d \( -name '*_ttt' -o -name '*_old' -o -name '*_bak' -o -name '* copy' \) -not -path '*/node_modules/*' -not -path './commercial/*' -not -path './.git/*'); \
	if [ -n "$$bad" ]; then echo "legacy package copies are not allowed:"; echo "$$bad"; exit 1; fi

check: fmt vet lint-layout test-race ## Everything CI runs (Go only; see client-check)

# Public SDK and interoperability checks build independently of Go.
NPM ?= npm

client-install: ## Install public SDK dependencies
	$(NPM) --prefix packages/client ci

client-build: ## Build the public transport/crypto SDK
	$(NPM) --prefix packages/client run build

client-test: ## Check SDK types and cryptographic interoperability
	$(NPM) --prefix packages/client run typecheck
	$(NPM) --prefix packages/client test

client-check: client-test client-build ## Verify the public SDK

public-source: ## Export an allowlisted public source snapshot without private code
	python3 scripts/export-public.py --output dist/wappie-source.tar.gz

tidy: ## Tidy modules
	$(GO) mod tidy

dev-up: ## Start Postgres + MinIO
	docker compose -f docker-compose.dev.yml up -d
	@echo "postgres :5433  minio :9000 (console :9001)"

dev-down: ## Stop and remove dev volumes
	docker compose -f docker-compose.dev.yml down -v
