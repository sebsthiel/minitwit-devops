.PHONY: staticcheck gofmt hadolint analysis checkmake all runlocalswarm buildlocal swarm createnetwork env deploy clean test 

# Use ONE shell per recipe. Does not work across recipes.
.ONESHELL:
SHELL := /bin/bash

# Make .env variables accessible to all recipes with $(VARIABLE_NAME)
include .env

# Export all make variables to shell. Recipes can use $VARIABLE_NAME. Especially useful if we use python scripts to run stuff as we might want to expose variables instead of passing them.
# export

all: staticcheck gofmt hadolint checkmake

staticcheck:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

gofmt:
	gofmt -l .

hadolint:
	docker run --rm -i hadolint/hadolint < Dockerfile.api
	docker run --rm -i hadolint/hadolint < Dockerfile.web

checkmake:
	go run github.com/checkmake/checkmake/cmd/checkmake@latest Makefile

test:
	@echo "No tests defined"

# FOR running SWARM locally:
STACK_NAME=minitwit
MONITORING_STACK=monitoring
NETWORK=minitwit-network

runlocalswarm: buildlocal initswarm createnetwork deploywebapi

buildlocal:
	docker build -t minitwit-api:dev -f Dockerfile.api .
	docker build -t minitwit-web:dev -f Dockerfile.web .

initswarm:
	@if [ "$$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]; then \
		echo "Initializing swarm..."; docker swarm init; \
	else echo "Swarm already active"; fi

createnetwork:
	@if ! docker network ls --format '{{.Name}}' | grep -w $(NETWORK) >/dev/null; then \
		echo "Creating overlay network..."; docker network create --driver overlay --attachable $(NETWORK); \
	else echo "Network already exists"; fi

createnetwork2:
	@echo "Ensuring overlay network exists..."
	@docker network inspect $(NETWORK) >/dev/null 2>&1 || \
		docker network create --driver overlay --attachable $(NETWORK)

	@echo "Waiting for Swarm network propagation..."
	@i=0; \
	until docker network inspect $(NETWORK) >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -gt 10 ]; then \
			echo "Network did not become ready in time"; exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "Network ready"

deploywebapi:
	docker compose -f docker-compose.local-db.yml up -d
	docker stack deploy -c docker-compose.develop.yml $(STACK_NAME)

deploymonitoring:
	docker stack deploy -c docker-compose.monitoring.yml $(MONITORING_STACK)

clean:
	docker stack rm $(STACK_NAME) || true
	docker stack rm $(MONITORING_STACK) || true
	docker compose -f docker-compose.local-db.yml down || true
	docker network rm $(NETWORK);

deployall: clean buildlocal initswarm createnetwork2 deploywebapi deploymonitoring
	watch -n 2 docker service ls

service_watch:
	watch -n 2 docker service ls

log_web:
	docker service logs minitwit_web -f --tail 20

log_api:
	docker service logs minitwit_api -f --tail 20

log_proxy:
	docker service logs minitwit_nginx -f --tail 20

log_grafana:
	docker service logs monitoring_grafana -f --tail 20

log_loki:
	docker service logs monitoring_loki -f --tail 20

log_prometheus:
	docker service logs monitoring_prometheus -f --tail 20

log_promtail:
	docker service logs monitoring_promtail -f --tail 20