# web-mcp — build, test, and run the MCP server locally or in Docker.
# Run `make help` for all targets. Deployment is via docker-compose.yml (see README).

APP         := web-mcp
IMAGE       ?= $(APP):latest
DOCKER_PORT ?= 8788

.DEFAULT_GOAL := help
.PHONY: help build test lint fmt run stdio docker-build docker-run

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the release binary
	cargo build --release --locked

test: ## Run the test suite
	cargo test --locked

lint: ## Check formatting and clippy (warnings are errors)
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings

fmt: ## Format the code
	cargo fmt

run: ## Run the HTTP server in the foreground (uses ./.env)
	cargo run --release -- serve

stdio: ## Run the stdio MCP server in the foreground (uses ./.env)
	cargo run --release -- stdio

docker-build: ## Build the Docker image ($(IMAGE))
	docker build -t $(IMAGE) .

docker-run: docker-build ## Run the image on 127.0.0.1:$(DOCKER_PORT) using ./.env
	docker run --rm -it --env-file .env -e WEB_MCP_BIND=0.0.0.0:8787 \
		--read-only --cap-drop ALL -p 127.0.0.1:$(DOCKER_PORT):8787 $(IMAGE)
