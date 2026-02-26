FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TZ=Europe/Moscow

WORKDIR /app

# apt-get runs WITHOUT proxy (SOCKS5 not supported by apt)
# Docker pre-defined args (HTTP_PROXY etc.) are auto-injected — must unset explicitly
RUN http_proxy="" https_proxy="" HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" all_proxy="" \
    apt-get update && \
    http_proxy="" https_proxy="" HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" all_proxy="" \
    apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev libpq-dev gcc curl && \
    ln -sf /usr/bin/python3 /usr/bin/python && \
    rm -rf /var/lib/apt/lists/*

# Install pysocks without proxy (needed for SOCKS5 proxy support in pip)
RUN http_proxy="" https_proxy="" all_proxy="" ALL_PROXY="" \
    pip install --no-cache-dir pysocks

# pip supports SOCKS5 proxy via build args
ARG ALL_PROXY=""
COPY requirements.txt .
RUN ALL_PROXY=${ALL_PROXY} \
    http_proxy=${ALL_PROXY} \
    https_proxy=${ALL_PROXY} \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/static /app/agent_packages /app/storcli_packages /app/logs /app/uploads/agent_logs

# Include pre-built agent RPM if present
COPY agent_packages/ /app/agent_packages/

EXPOSE 8000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
