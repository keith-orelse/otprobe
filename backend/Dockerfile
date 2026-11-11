FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Mosquitto for the bundled MQTT broker (MQTT_BROKER=bundled): OTProbe runs it as a child process.
RUN apt-get update && apt-get install -y --no-install-recommends mosquitto && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY rules/ /app/rules/
EXPOSE 8000 8883
# Single worker by design (see docs/ARCHITECTURE.md §6).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
