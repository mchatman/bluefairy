.PHONY: run build clean test migrate up down logs

run:
	go run cmd/api/main.go cmd/api/routes.go

build:
	go build -o bin/api cmd/api/main.go cmd/api/routes.go

clean:
	rm -rf bin/

test:
	go test -v ./...

migrate-up:
	migrate -path migrations -database "${DATABASE_URL}" up

migrate-down:
	migrate -path migrations -database "${DATABASE_URL}" down

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

dev:
	air