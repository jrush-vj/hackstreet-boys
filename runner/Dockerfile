# Build context is the repo root (see docker-compose.yml).
FROM python:3.11-slim
ENV PORT=8005 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY runner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY runner/ /app/
CMD uvicorn app.main:app --host 0.0.0.0 --port $PORT
