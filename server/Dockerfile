FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy static files to shared volume
RUN mkdir -p /app/static && \
    cp -r /app/app/static/* /app/static/ 2>/dev/null || true

EXPOSE 8000

CMD ["python", "-m", "app.main"]
