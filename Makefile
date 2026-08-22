-include .env

export

MIGRATIONS_DIR=internal/db/migrations
DB_URL=postgres://$(DB_USERNAME):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_DATABASE)?sslmode=disable

run:
	@echo "Running centrauth..."
	go run ./cmd/centrauth/main.go

test:
	@echo "Running unit tests..."
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...

migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" up

migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" down

migrate-status:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" status

migrate-create:
	goose -dir $(MIGRATIONS_DIR) create $(name) sql
