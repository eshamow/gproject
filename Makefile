.PHONY: run dev test db-reset deps build clean docker-build docker-run docker-stop docker-logs

# Go commands
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

# Docker commands
docker-build:
	docker build -t gproject:latest .

docker-run:
	docker-compose up --build

docker-run-prod:
	docker-compose -f docker-compose.prod.yml up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-clean:
	docker-compose down -v
	docker image prune -f