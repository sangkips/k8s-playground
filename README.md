# k8s-playground

## What this is

Scaffold for a “K8s Guided Learning Platform” backend written in Go.
It is a guided production deployment learning platform structured like a course, but the curriculum is the actual deployment process. Users don't just check code; they walk through a real DevOps workflow, step by step, with the system validating each gate before they can proceed. Think of it as Duolingo meets a real CI/CD pipeline.

Current scope:
- HTTP API server with `GET /healthz`
- PostgreSQL schema migrations via `golang-migrate` (`./migrations`)

## Prerequisites

- PostgreSQL 15+

## Environment variables

`DATABASE_URL` (optional): PostgreSQL connection string.

Example:
`DATABASE_URL=postgres://user:password@localhost:5432/k8s_playground?sslmode=disable`

Optional:
- `HTTP_ADDR` (default `:8080`)
- `RUN_MIGRATIONS_ON_START` (default `false`)
- `MIGRATIONS_DIR` (default `./migrations`)
- Local DB fallback when `DATABASE_URL` is not set:
  - `LOCAL_DB_HOST` (default `localhost`)
  - `LOCAL_DB_PORT` (default `5432`)
  - `LOCAL_DB_USER` (default `postgres`)
  - `LOCAL_DB_PASSWORD` (default empty)
  - `LOCAL_DB_NAME` (default `k8s`)
  - `LOCAL_DB_SSLMODE` (default `disable`)

## Local workflow

1. Create/connect to your PostgreSQL database.
2. Run schema migrations:
   - `make migrate-up`
   - `make migrate-status`
3. Start the API:
   - `make run`

To run migrations automatically on startup (useful for development):
- set `RUN_MIGRATIONS_ON_START=true` before `make run`.
