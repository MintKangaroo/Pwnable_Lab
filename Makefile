.PHONY: install migrate test coverage lint typecheck dev-backend dev-frontend build docker-up docker-dev docker-prod

install:
	python3 -m pip install -e "./backend[dev]"
	cd frontend && npm ci

migrate:
	cd backend && alembic upgrade head

test:
	cd backend && pytest

coverage:
	cd backend && pytest --cov=pwnable_lab --cov-report=term-missing

lint:
	cd backend && black --check pwnable_lab tests migrations
	cd backend && ruff check pwnable_lab tests migrations
	cd backend && mypy pwnable_lab
	cd frontend && npm run lint

typecheck:
	cd frontend && npm run typecheck

dev-backend:
	cd backend && uvicorn pwnable_lab.api.app:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

docker-up:
	docker compose up --build

docker-dev:
	docker compose -f docker-compose.dev.yml up --build

docker-prod:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build
