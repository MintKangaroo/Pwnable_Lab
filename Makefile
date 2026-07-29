.PHONY: install test coverage dev-backend dev-frontend build docker-up

install:
	python3 -m pip install -e "./backend[dev]"
	cd frontend && npm ci

test:
	cd backend && pytest

coverage:
	cd backend && pytest --cov=pwnable_lab --cov-report=term-missing

dev-backend:
	cd backend && uvicorn pwnable_lab.api.app:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

docker-up:
	docker compose up --build
