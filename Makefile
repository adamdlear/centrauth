run:
	@echo "Running centrauth..."
	go run ./cmd/centrauth/main.go

test:
	@echo "Running unit tests..."
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...
