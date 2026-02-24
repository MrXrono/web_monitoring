#!/bin/bash
#
# RAID Monitor - Installation and Management Script
# Usage: ./web-monitoring.sh [install|update|reinstall|purge|status|logs|backup]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="raid-monitor"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
ENV_FILE="${SCRIPT_DIR}/.env"
BACKUP_DIR="${SCRIPT_DIR}/backups"
PROXY_FILE="${SCRIPT_DIR}/.proxy"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

load_proxy() {
    if [ -n "${BUILD_PROXY:-}" ]; then
        export BUILD_PROXY
        return
    fi
    if [ -f "$PROXY_FILE" ]; then
        BUILD_PROXY="$(cat "$PROXY_FILE" | tr -d '[:space:]')"
        if [ -n "$BUILD_PROXY" ]; then
            export BUILD_PROXY
            log_info "Build proxy: $BUILD_PROXY"
        fi
    fi
}

do_proxy() {
    local action="${1:-}"
    case "$action" in
        set)
            local url="${2:-}"
            if [ -z "$url" ]; then
                log_error "Usage: $0 proxy set <proxy_url>"
                log_info "Example: $0 proxy set socks5://rkn.vniizht.lan:10808"
                exit 1
            fi
            echo "$url" > "$PROXY_FILE"
            chmod 600 "$PROXY_FILE"
            log_info "Build proxy set: $url"
            ;;
        remove)
            rm -f "$PROXY_FILE"
            unset BUILD_PROXY 2>/dev/null || true
            log_info "Build proxy removed"
            ;;
        show)
            if [ -f "$PROXY_FILE" ]; then
                log_info "Build proxy: $(cat "$PROXY_FILE")"
            else
                log_info "Build proxy: not configured"
            fi
            ;;
        *)
            echo "Usage: $0 proxy {set <url>|remove|show}"
            ;;
    esac
}

check_requirements() {
    local missing=0
    for cmd in docker; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "$cmd is not installed"
            missing=1
        fi
    done

    if ! docker compose version &>/dev/null 2>&1; then
        if ! docker-compose version &>/dev/null 2>&1; then
            log_error "docker compose (v2) or docker-compose is not installed"
            missing=1
        fi
    fi

    if [ $missing -eq 1 ]; then
        log_error "Please install missing requirements and try again"
        exit 1
    fi
}

compose_cmd() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
    else
        docker-compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
    fi
}

generate_env() {
    if [ -f "$ENV_FILE" ]; then
        log_info ".env file already exists, skipping generation"
        return
    fi

    log_step "Generating .env file with random secrets..."

    POSTGRES_PASSWORD=$(openssl rand -hex 32)
    SECRET_KEY=$(openssl rand -hex 32)
    ENCRYPTION_KEY=$(openssl rand -hex 16)
    ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -d '=/+' | head -c 16)

    cat > "$ENV_FILE" << EOF
# RAID Monitor - Auto-generated configuration
# Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

POSTGRES_DB=raidmonitor
POSTGRES_USER=raidmonitor
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

SECRET_KEY=${SECRET_KEY}
ENCRYPTION_KEY=${ENCRYPTION_KEY}

ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_FORCE_ENABLE=false

TELEGRAM_BOT_TOKEN_ENCRYPTED=
TELEGRAM_CHAT_ID=

DEBUG=false
LOG_LEVEL=INFO
APP_HOST=0.0.0.0
APP_PORT=8000
EOF

    chmod 600 "$ENV_FILE"
    echo ""
    log_info "=========================================="
    log_info "  Initial admin credentials:"
    log_info "  Username: admin"
    log_info "  Password: ${ADMIN_PASSWORD}"
    log_info "=========================================="
    log_warn "Save the password! It is stored in .env file."
    echo ""
}

generate_ssl() {
    local ssl_dir="${SCRIPT_DIR}/nginx/ssl"
    mkdir -p "$ssl_dir"

    if [ -f "${ssl_dir}/server.crt" ] && [ -f "${ssl_dir}/server.key" ]; then
        log_info "SSL certificate already exists, skipping"
        return
    fi

    log_step "Generating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout "${ssl_dir}/server.key" \
        -out "${ssl_dir}/server.crt" \
        -subj "/CN=raid-monitor/O=RAID Monitor" \
        -addext "subjectAltName=DNS:localhost,DNS:raid-monitor" \
        2>/dev/null

    log_info "SSL certificate generated"
}

do_install() {
    log_info "Installing RAID Monitor..."
    echo ""

    check_requirements
    generate_env
    generate_ssl
    load_proxy

    log_step "Building Docker images..."
    compose_cmd build --no-cache

    log_step "Starting services..."
    compose_cmd up -d

    log_step "Waiting for services to be ready..."
    sleep 10

    if compose_cmd ps | grep -q "Up"; then
        echo ""
        log_info "=========================================="
        log_info "  RAID Monitor installed successfully!"
        log_info "  Access: https://localhost"
        log_info "=========================================="
    else
        log_error "Some services failed to start. Check logs:"
        compose_cmd logs --tail=50
        exit 1
    fi
}

do_update() {
    log_info "Updating RAID Monitor..."
    check_requirements
    load_proxy

    if [ -d "${SCRIPT_DIR}/.git" ]; then
        log_step "Pulling latest changes..."
        cd "$SCRIPT_DIR" && git pull
    fi

    log_step "Rebuilding Docker images..."
    compose_cmd build

    log_step "Restarting services..."
    compose_cmd up -d

    sleep 5
    log_info "RAID Monitor updated successfully!"
}

do_reinstall() {
    log_info "Reinstalling RAID Monitor (keeping database)..."
    check_requirements
    load_proxy

    log_step "Stopping services..."
    compose_cmd down

    log_step "Rebuilding Docker images..."
    compose_cmd build --no-cache

    log_step "Starting services..."
    compose_cmd up -d

    sleep 10
    log_info "RAID Monitor reinstalled successfully!"
}

do_purge() {
    log_warn "This will DELETE ALL DATA including the database!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Cancelled"
        exit 0
    fi

    log_info "Purging RAID Monitor..."
    check_requirements

    log_step "Stopping services and removing volumes..."
    compose_cmd down -v

    log_step "Removing .env file..."
    rm -f "$ENV_FILE"

    log_step "Removing SSL certificates..."
    rm -f "${SCRIPT_DIR}/nginx/ssl/server.crt" "${SCRIPT_DIR}/nginx/ssl/server.key"

    log_step "Reinstalling from scratch..."
    do_install
}

do_status() {
    check_requirements
    echo ""
    log_info "RAID Monitor Service Status:"
    echo ""
    compose_cmd ps
    echo ""

    # Check each service
    for svc in nginx web postgres; do
        if compose_cmd ps "$svc" 2>/dev/null | grep -q "Up\|running"; then
            echo -e "  ${GREEN}●${NC} $svc - running"
        else
            echo -e "  ${RED}●${NC} $svc - stopped"
        fi
    done
    echo ""
}

do_logs() {
    local service="${1:-}"
    local lines="${2:-100}"

    check_requirements
    if [ -n "$service" ]; then
        compose_cmd logs --tail="$lines" -f "$service"
    else
        compose_cmd logs --tail="$lines" -f
    fi
}

do_backup() {
    check_requirements
    mkdir -p "$BACKUP_DIR"

    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${BACKUP_DIR}/raidmonitor_${timestamp}.sql.gz"

    log_step "Backing up database..."

    source "$ENV_FILE" 2>/dev/null || true
    local db_user="${POSTGRES_USER:-raidmonitor}"
    local db_name="${POSTGRES_DB:-raidmonitor}"

    compose_cmd exec -T postgres pg_dump -U "$db_user" "$db_name" | gzip > "$backup_file"

    if [ -s "$backup_file" ]; then
        log_info "Backup saved to: $backup_file"
        log_info "Size: $(du -h "$backup_file" | cut -f1)"
    else
        log_error "Backup failed!"
        rm -f "$backup_file"
        exit 1
    fi
}

do_restore() {
    local backup_file="$1"
    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log_error "Usage: $0 restore <backup_file.sql.gz>"
        exit 1
    fi

    check_requirements
    source "$ENV_FILE" 2>/dev/null || true
    local db_user="${POSTGRES_USER:-raidmonitor}"
    local db_name="${POSTGRES_DB:-raidmonitor}"

    log_warn "This will replace the current database with the backup!"
    read -p "Continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Cancelled"
        exit 0
    fi

    log_step "Restoring database from $backup_file..."
    gunzip -c "$backup_file" | compose_cmd exec -T postgres psql -U "$db_user" -d "$db_name"
    log_info "Database restored successfully!"
}

usage() {
    echo ""
    echo "RAID Monitor - Management Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  install       Install RAID Monitor (build, generate configs, start)"
    echo "  update        Update RAID Monitor (pull, rebuild, restart)"
    echo "  reinstall     Reinstall (stop, rebuild, start - keeps database)"
    echo "  purge         Full reinstall with database deletion"
    echo "  status        Show service status"
    echo "  logs [svc]    Show logs (optional: nginx, web, postgres)"
    echo "  backup        Backup database"
    echo "  restore <f>   Restore database from backup file"
    echo "  proxy set <u> Set build proxy (socks5/http)"
    echo "  proxy remove  Remove build proxy"
    echo "  proxy show    Show current build proxy"
    echo ""
    echo "Examples:"
    echo "  $0 install"
    echo "  $0 proxy set socks5://rkn.vniizht.lan:10808"
    echo "  $0 update"
    echo "  $0 logs web"
    echo "  $0 backup"
    echo "  $0 restore backups/raidmonitor_20260224.sql.gz"
    echo ""
}

# Main
case "${1:-}" in
    install)    do_install ;;
    update)     do_update ;;
    reinstall)  do_reinstall ;;
    purge)      do_purge ;;
    status)     do_status ;;
    logs)       do_logs "$2" "$3" ;;
    backup)     do_backup ;;
    restore)    do_restore "$2" ;;
    proxy)      do_proxy "$2" "$3" ;;
    *)          usage ;;
esac
