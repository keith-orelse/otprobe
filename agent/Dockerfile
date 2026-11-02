FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY agent/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/ ./
CMD ["python", "-m", "otprobe_agent"]
