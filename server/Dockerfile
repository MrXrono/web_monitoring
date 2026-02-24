FROM python:3.11-slim

WORKDIR /app

ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG ALL_PROXY=""
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY} all_proxy=${ALL_PROXY}

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV http_proxy="" https_proxy="" all_proxy=""

COPY . .

RUN mkdir -p /app/static

EXPOSE 8000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
