.PHONY: staticcheck gofmt hadolint analysis checkmake all runlocalswarm buildlocal swarm createnetwork env deploy clean test delete_all_volumes

# Use ONE shell per recipe. Does not work across recipes.
.ONESHELL:
SHELL := /bin/bash

# Make .env variables accessible to all recipes with $(VARIABLE_NAME)
# include .env

# Export all make variables to shell. Recipes can use $VARIABLE_NAME. Especially useful if we use python scripts to run stuff as we might want to expose variables instead of passing them.
# export

all: staticcheck gofmt hadolint checkmake semgrep

semgrep:
	docker run --rm -v "$(PWD):/src" returntocorp/semgrep semgrep --config=auto /src

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

deploywebapi:
	@set -a; source .env; set +a;
	docker compose -f docker-compose.local-db.yml up -d
	docker stack deploy -c docker-compose.develop.yml $(STACK_NAME)

deploymonitoring:
	@set -a; source .env; set +a;
	docker stack deploy -c docker-compose.monitoring.yml $(MONITORING_STACK)

clean:
	docker stack rm $(STACK_NAME) || true
	docker stack rm $(MONITORING_STACK) || true
	docker compose -f docker-compose.local-db.yml down || true
	docker network rm $(NETWORK) || true;

delete_grafana_volume:
	docker volume rm monitoring_grafana-storage

delete_loki_volume:
	docker volume rm monitoring_loki-storage

delete_prometheus_volume:
	docker volume rm monitoring_prometheus-storage

delete_all_volumes: delete_grafana_volume delete_loki_volume delete_prometheus_volume

deployall: createnetwork buildlocal initswarm  deploywebapi deploymonitoring
	watch -n 2 docker service ls

deploy_local_simulator:
	cd ./test
	python3 minitwit_simulator.py http://127.0.0.1/api

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

# Used to cleanup VM by removing: unused images, stopped containers, unused volumes, build cache
# and other temporary files.
aggressive_docker_clean:
	docker system df
	docker system prune -a --volumes
	sudo journalctl --vacuum-size=100M
	sudo apt-get clean
	sudo apt-get autoremove -y
