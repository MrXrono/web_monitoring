.PHONY: help install build up down restart logs status backup clean rpm-agent

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install (first time setup)
	./web-monitoring.sh install

build: ## Build Docker images
	docker compose build

up: ## Start all services
	docker compose up -d

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

logs: ## View logs (use: make logs SVC=web)
	docker compose logs -f $(SVC)

status: ## Show service status
	docker compose ps

backup: ## Backup database
	./web-monitoring.sh backup

clean: ## Remove containers and volumes
	docker compose down -v

rpm-agent: ## Build agent RPM (requires rpmbuild)
	cd agent && rpmbuild -bb raid-agent.spec
