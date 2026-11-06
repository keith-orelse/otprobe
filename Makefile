.PHONY: up down dev-api dev-web test lint
up:            ## live mode (Linux host)
	docker compose up --build
down:
	docker compose down
dev-api:       ## live mode; set OTPROBE_*_PASSWORD or read the generated ones in the log
	cd backend && .venv/bin/uvicorn app.main:app --port 8000 --reload
dev-web:
	cd frontend && npm run dev
test:          ## the simulator now lives in backend/tests/sim and runs only inside the tests
	cd backend && .venv/bin/pytest -q
lint:
	cd backend && .venv/bin/ruff check app tests && .venv/bin/lint-imports
