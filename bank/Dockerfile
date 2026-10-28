FROM python:3.11-slim
WORKDIR /app
ENV PORT=8001 PYTHONUNBUFFERED=1 PYTHONPATH=/app BANK_DB_PATH=/data/bank.db
COPY bank/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY shared /app/shared
COPY bank /app/bank
RUN mkdir -p /data
EXPOSE 8001
CMD ["uvicorn", "bank.app.main:app", "--host", "0.0.0.0", "--port", "8001"]
