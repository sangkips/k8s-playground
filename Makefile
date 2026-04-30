.PHONY: build run test migrate-up migrate-down migrate-status

GO ?= go

ifneq (,$(wildcard ./.env))
include .env
export
endif

MIGRATIONS_DIR ?= ./migrations

build:
	$(GO) build ./...

run:
	$(GO) run ./cmd/api

test:
	$(GO) test ./...

migrate-up:
	MIGRATIONS_DIR="$(MIGRATIONS_DIR)" $(GO) run ./cmd/migrate -action=up

migrate-down:
	MIGRATIONS_DIR="$(MIGRATIONS_DIR)" $(GO) run ./cmd/migrate -action=down

migrate-status:
	MIGRATIONS_DIR="$(MIGRATIONS_DIR)" $(GO) run ./cmd/migrate -action=status

