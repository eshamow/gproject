.PHONY: run dev test db-reset deps

run:
	go run cmd/web/main.go

dev:
	air -c .air.toml || go run cmd/web/main.go

test:
	go test -v ./...

db-reset:
	rm -f data/gproject.db
	go run cmd/web/main.go migrate

deps:
	go mod download
	go mod tidy

build:
	go build -o bin/gproject cmd/web/main.go

clean:
	rm -f data/gproject.db
	rm -rf bin/