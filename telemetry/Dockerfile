FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY telemetry/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY telemetry/ ./
CMD ["python", "-m", "otprobe_telemetry"]
