.PHONY: staticcheck gofmt hadolint analysis checkmake all clean test

all: staticcheck gofmt hadolint checkmake

staticcheck:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...


gofmt:
	gofmt -l .


hadolint:
	docker run --rm -i hadolint/hadolint < Dockerfile

checkmake:
	go run github.com/checkmake/checkmake/cmd/checkmake@latest Makefile

clean:
	@echo "Nothing to clean"

test:
	@echo "No tests defined"

runlocal:
	docker build -t minitwitimage:local .
	MINITWIT_IMAGE=minitwitimage:local docker compose up -d