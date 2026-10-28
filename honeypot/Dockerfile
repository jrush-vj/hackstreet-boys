FROM python:3.11-slim
WORKDIR /app
COPY honeypot/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY honeypot /app/honeypot
EXPOSE 8002
CMD ["uvicorn", "honeypot.app.main:app", "--host", "0.0.0.0", "--port", "8002"]
