#!/bin/bash
# ============================================================
# cleanup-server-data.sh
# Очистка данных мониторинга (контроллеры, диски, события и т.д.)
# Сохраняет: servers, api_keys — агентам НЕ нужно перерегистрироваться
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# --- Загрузка .env ---
if [ ! -f "$ENV_FILE" ]; then
    echo "[ERROR] Файл .env не найден: $ENV_FILE"
    exit 1
fi

source "$ENV_FILE"

# Проверка переменных
for var in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD; do
    if [ -z "${!var:-}" ]; then
        echo "[ERROR] Переменная $var не задана в .env"
        exit 1
    fi
done

POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

# --- Определение способа подключения ---
if command -v psql &>/dev/null; then
    PSQL_CMD="psql"
elif docker compose ps postgres 2>/dev/null | grep -q "running"; then
    PSQL_CMD="docker compose exec -T postgres psql"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "postgres"; then
    CONTAINER=$(docker ps --format '{{.Names}}' | grep postgres | head -1)
    PSQL_CMD="docker exec -i $CONTAINER psql"
else
    echo "[ERROR] PostgreSQL недоступен: psql не найден и контейнер не запущен"
    exit 1
fi

CONN="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"

echo "============================================"
echo "  RAID Monitor — Очистка данных мониторинга"
echo "============================================"
echo ""
echo "Будут УДАЛЕНЫ:"
echo "  - smart_history        (история SMART)"
echo "  - controller_events    (события контроллеров)"
echo "  - physical_drives      (физические диски)"
echo "  - virtual_drives       (виртуальные диски)"
echo "  - bbu_units            (BBU/CacheVault)"
echo "  - controllers          (контроллеры)"
echo "  - software_raids       (программные RAID)"
echo "  - alert_history        (история алертов)"
echo ""
echo "Будут СОХРАНЕНЫ:"
echo "  - servers              (записи серверов)"
echo "  - api_keys             (ключи агентов)"
echo "  - users                (пользователи)"
echo "  - alert_rules          (правила алертов)"
echo "  - settings             (настройки)"
echo "  - agent_packages       (пакеты агента)"
echo "  - audit_log            (журнал аудита)"
echo ""
echo "Агентам НЕ потребуется повторная регистрация."
echo ""
read -rp "Продолжить? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Отменено."
    exit 0
fi

echo ""
echo "[*] Очистка данных..."

$PSQL_CMD "$CONN" <<'SQL'
BEGIN;

-- Порядок удаления: от дочерних к родительским (FK constraints)
TRUNCATE smart_history CASCADE;
TRUNCATE controller_events CASCADE;
TRUNCATE physical_drives CASCADE;
TRUNCATE virtual_drives CASCADE;
TRUNCATE bbu_units CASCADE;
TRUNCATE controllers CASCADE;
TRUNCATE software_raids CASCADE;
TRUNCATE alert_history CASCADE;

-- Сброс кэшированного отчёта и статуса серверов
UPDATE servers SET
    last_report = NULL,
    status = 'unknown',
    last_seen = NULL;

COMMIT;
SQL

if [ $? -eq 0 ]; then
    echo ""
    echo "[OK] Данные мониторинга очищены."
    echo "     Серверы и API-ключи сохранены — агенты продолжат работу."
else
    echo ""
    echo "[ERROR] Ошибка при очистке данных."
    exit 1
fi
