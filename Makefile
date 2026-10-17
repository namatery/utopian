VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race cover vet lint vuln fuzz check

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/utopian ./cmd/utopian

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Run each fuzz target for FUZZTIME (default 30s).
FUZZTIME ?= 30s
fuzz:
	go test ./pkg/sign -run '^$$' -fuzz FuzzParseHeader -fuzztime $(FUZZTIME)

# gosec runs as part of golangci-lint.
check: vet race lint vuln
