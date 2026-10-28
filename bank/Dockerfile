FROM python:3.11-slim
WORKDIR /app
COPY bank/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY bank /app/bank
ENV BANK_DB_PATH=/data/bank.db
ENV PORT=8001
RUN mkdir -p /data
EXPOSE 8001
CMD ["uvicorn", "bank.app.main:app", "--host", "0.0.0.0", "--port", "8001"]
