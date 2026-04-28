.PHONY: staticcheck gofmt hadolint analysis checkmake all runlocalswarm buildlocal swarm createnetwork env deploy clean test 

all: staticcheck gofmt hadolint checkmake semgrep

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

runlocalswarm: buildlocal initswarm createnetwork setenv deploywebapi

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

runlocalmonitoring:
	docker compose -f docker-compose.monitoring.yml up -d

semgrep:
	docker run --rm -v "$(PWD):/src" returntocorp/semgrep semgrep --config=auto /src
setenv:
	@set -a && [ -f .env ] && . ./.env || true && set +a

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
