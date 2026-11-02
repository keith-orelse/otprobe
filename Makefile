.PHONY: up down dev-api dev-web test lint
up:
	docker compose up --build
down:
	docker compose down
dev-api:
	cd backend && .venv/bin/uvicorn app.main:app --port 8000 --reload
dev-web:
	cd frontend && npm run dev
test:
	cd backend && .venv/bin/pytest -q
lint:
	cd backend && .venv/bin/ruff check app tests && .venv/bin/lint-imports
