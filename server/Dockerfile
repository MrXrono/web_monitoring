FROM python:3.11-slim

WORKDIR /app

# apt-get runs WITHOUT proxy (SOCKS5 not supported by apt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc curl && \
    rm -rf /var/lib/apt/lists/*

# pip supports SOCKS5 proxy via build args
ARG ALL_PROXY=""
COPY requirements.txt .
RUN ALL_PROXY=${ALL_PROXY} \
    http_proxy=${ALL_PROXY} \
    https_proxy=${ALL_PROXY} \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/static

EXPOSE 8000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
