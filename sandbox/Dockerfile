# Build context is the repo root (see docker-compose.yml).
FROM python:3.11-slim
ENV PORT=8003 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY sandbox/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY sandbox/ /app/
CMD uvicorn app.main:app --host 0.0.0.0 --port $PORT
