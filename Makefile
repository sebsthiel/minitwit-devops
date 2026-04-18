.PHONY: staticcheck gofmt hadolint analysis checkmake all clean test

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

clean:
	docker compose \
  -f docker-compose.yml \
  -f docker-compose.develop.yml \
  -f docker-compose.monitoring.yml \
  down

test:
	@echo "No tests defined"

runlocal:
	docker compose -f docker-compose.develop.yml up -d

runlocalmonitoring:
	docker compose -f docker-compose.monitoring.yml up -d