.PHONY: up up-sim down dev-api dev-api-sim dev-web test lint
up:            ## live mode (Linux host)
	docker compose up --build
up-sim:        ## simulated POC
	ADAPTER_MODE=simulated docker compose --profile simulated up --build
down:
	docker compose --profile simulated down
dev-api:       ## live mode; set OTPROBE_*_PASSWORD or read the generated ones in the log
	cd backend && .venv/bin/uvicorn app.main:app --port 8000 --reload
dev-api-sim:
	cd backend && ADAPTER_MODE=simulated .venv/bin/uvicorn app.main:app --port 8000 --reload
dev-web:
	cd frontend && npm run dev
test:
	cd backend && .venv/bin/pytest -q
lint:
	cd backend && .venv/bin/ruff check app tests && .venv/bin/lint-imports
