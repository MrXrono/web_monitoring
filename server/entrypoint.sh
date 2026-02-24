#!/bin/sh
# Sync static files to the shared volume on every startup
# This ensures new vendor/CSS/JS files are always available to nginx
cp -r /app/app/static/* /app/static/ 2>/dev/null || true

exec python -m app.main
