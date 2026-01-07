.PHONY: all build test clean build-all lint

# Default target: build and test
all: build test

# Build for current platform
build:
	go build -o cage .

# Run all tests
test:
	go test -v ./...

# Build for all release platforms
build-all: clean
	GOOS=darwin GOARCH=amd64 go build -o dist/cage-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o dist/cage-darwin-arm64 .
	GOOS=linux GOARCH=amd64 go build -o dist/cage-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o dist/cage-linux-arm64 .
	@echo "Built all targets in dist/"
	@ls -la dist/

# Clean build artifacts
clean:
	rm -f cage cage-test
	rm -f cage-linux-* cage-darwin-*
	rm -rf dist/

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Quick check: build all platforms without output files
check:
	@echo "Checking darwin/amd64..." && GOOS=darwin GOARCH=amd64 go build .
	@echo "Checking darwin/arm64..." && GOOS=darwin GOARCH=arm64 go build .
	@echo "Checking linux/amd64..." && GOOS=linux GOARCH=amd64 go build .
	@echo "Checking linux/arm64..." && GOOS=linux GOARCH=arm64 go build .
	@echo "✅ All platforms compile successfully"

# Run goreleaser locally (dry-run)
release-dry-run:
	goreleaser release --snapshot --clean
