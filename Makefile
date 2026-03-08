.PHONY: build test lint clean

# Build the CLI binary
build:
	go build -o bin/envsh ./cmd/cli

# Run all tests with race detector
test:
	go test -race ./...

# Run linter
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Download dependencies
deps:
	go mod download
	go mod tidy

# Run crypto tests only
test-crypto:
	go test -race -v ./pkg/crypto/...

# Run tests with coverage
coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
