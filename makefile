.PHONY: build help

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	@cd demo-fake-api && npm install && cd ../plugin && go mod tidy

run: ## Start the demo
	docker compose up

build: ## Build caddy with the simple_rest_rbac plugin
	docker compose build
