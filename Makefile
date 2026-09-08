.PHONY: help run test test-race lint lint-layout vet fmt cover fuzz dev-up dev-down build tidy check \
	web-install web-build web-test web-check

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
	@out=$$(gofmt -l . | grep -v '^web/' || true); \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

# The whatsapp_server2 project rotted because a half-finished migration left
# API_ttt/ and mongo_ttt/ beside the real packages and nobody ever removed
# them. Fail the build rather than let that start.
lint-layout: ## Reject parallel legacy package copies
	@bad=$$(find . -type d \( -name '*_ttt' -o -name '*_old' -o -name '*_bak' -o -name '* copy' \) -not -path './web/node_modules/*' -not -path './.git/*'); \
	if [ -n "$$bad" ]; then echo "legacy package copies are not allowed:"; echo "$$bad"; exit 1; fi

check: fmt vet lint-layout test-race ## Everything CI runs (Go only; see web-check)

# --- the browser client ----------------------------------------------------
#
# Kept out of `check` on purpose: the Go build must not need a JavaScript
# toolchain installed. CI runs both in separate jobs.

NPM ?= npm

web-install: ## Install the web client's dependencies
	cd web && $(NPM) install

web-build: ## Build the web client into web/dist, which whatserverd serves
	cd web && $(NPM) run build

# The crypto tests here are the ones that matter most in the repo: they open
# vectors that Go sealed, so a divergence between the two implementations of
# the archive format fails on this side rather than on a user's messages.
web-test: ## Typecheck and test the web client
	cd web && $(NPM) run typecheck && $(NPM) run test

web-check: web-test web-build ## Everything CI runs for the web client

tidy: ## Tidy modules
	$(GO) mod tidy

dev-up: ## Start Postgres + MinIO
	docker compose -f docker-compose.dev.yml up -d
	@echo "postgres :5433  minio :9000 (console :9001)"

dev-down: ## Stop and remove dev volumes
	docker compose -f docker-compose.dev.yml down -v
