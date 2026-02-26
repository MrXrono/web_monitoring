# Server Installation / Установка сервера

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## English

### Requirements

| Component | Minimum |
|-----------|---------|
| OS | Any Linux with Docker support |
| Docker | 20.10+ with Docker Compose v2 |
| RAM | 2 GB (10 servers) / 4 GB (50 servers) / 8 GB (100+ servers) |
| Disk | 5 GB (10 servers) / 20 GB (50 servers) / 50 GB (100+ servers) |
| CPU | 1-4 vCPU depending on load |
| Network | Port 443 (HTTPS) open for agents |

### Step 1. Install Docker

**RHEL/CentOS 8/9:**

```bash
dnf install -y dnf-plugins-core
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
```

**Ubuntu/Debian:**

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Verify:

```bash
docker --version
docker compose version
```

### Step 2. Clone the Repository

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
```

### Step 3. Install

```bash
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

This will:
1. Generate `.env` file with random secrets (database password, JWT secret, encryption key)
2. Generate a self-signed SSL certificate
3. Build Docker images (nginx, web app, PostgreSQL)
4. Start all containers
5. Create the admin user
6. Display admin credentials in the terminal

**Save the admin password** — it is shown only once in the terminal and stored in the `.env` file.

### Step 4. Access the Web Interface

Open in browser: `https://<server-ip>`

Login with the admin credentials from step 3.

### Proxy Configuration (optional)

If the server requires a proxy to download Docker images during build:

```bash
./web-monitoring.sh proxy set socks5://proxy.example.com:1080
./web-monitoring.sh install
```

To remove proxy:

```bash
./web-monitoring.sh proxy remove
```

### Management Commands

| Command | Description |
|---------|-------------|
| `./web-monitoring.sh install` | First-time installation (build + start) |
| `./web-monitoring.sh update` | Update to latest version (git pull + rebuild + restart) |
| `./web-monitoring.sh reinstall` | Reinstall containers (preserves database) |
| `./web-monitoring.sh purge` | Full reinstall (deletes database!) |
| `./web-monitoring.sh status` | Show service status |
| `./web-monitoring.sh logs` | View all logs |
| `./web-monitoring.sh logs web` | View web application logs only |
| `./web-monitoring.sh backup` | Backup PostgreSQL database |
| `./web-monitoring.sh restore <file>` | Restore database from backup |
| `./web-monitoring.sh proxy set <url>` | Set build proxy |
| `./web-monitoring.sh proxy remove` | Remove build proxy |

### SSL Certificate Setup

#### Self-Signed (default)

A self-signed certificate is generated automatically on first start. Agents must use `ssl_verify: false` in their config.

#### Custom Certificate (via Web UI)

1. Go to **Settings → SSL**
2. Upload your certificate (`.crt` / `.pem`) and private key (`.key`)
3. The system validates that the certificate and key match
4. nginx is automatically reloaded

#### Custom Certificate (manual)

Place your files at:
- `nginx/ssl/server.crt` — certificate (PEM format)
- `nginx/ssl/server.key` — private key (PEM format)

Restart nginx:

```bash
docker compose restart nginx
```

### LDAP / Active Directory

1. Go to **Settings → LDAP**
2. Fill in the connection parameters:
   - **Server URL**: `ldap://dc.example.com` or `ldaps://dc.example.com:636`
   - **Bind DN**: `CN=svc_raid,OU=Service,DC=example,DC=com`
   - **Bind Password**: service account password
   - **Search Base**: `OU=Users,DC=example,DC=com`
   - **User Filter**: `(sAMAccountName={username})` (for AD)
   - **Admin Group**: `CN=RAID-Admins,OU=Groups,DC=example,DC=com` (optional)
3. Click **Test Connection** to verify
4. Enable LDAP authentication

> When LDAP is enabled and LDAP admin users exist, the local `admin` account is automatically disabled. To temporarily re-enable it, set `ADMIN_FORCE_ENABLE=true` in `.env` and restart. It auto-disables after 3 hours.

### Telegram Notifications

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token
2. Get the chat ID (send a message to [@userinfobot](https://t.me/userinfobot))
3. Go to **Settings → Telegram**
4. Enter the bot token and chat ID
5. Click **Send Test Message** to verify
6. Enable notifications

### Upload Agent Package

To allow agents to auto-install/auto-update from the server:

1. Go to **Settings → Agents**
2. Upload the `raid-agent-*.rpm` file in the "Agent Package" section
3. Agents will check for updates and download automatically

### Upload StorCLI Package

If agents need storcli64 to be auto-installed:

1. Go to **Settings → Agents**
2. Upload the `storcli64-*.rpm` file in the "StorCLI Package" section
3. Agents without storcli64 will download and install it automatically

### API Documentation

Set `DEBUG=true` in `.env` and restart:

```bash
# Edit .env
vi .env

# Restart
./web-monitoring.sh reinstall
```

API docs available at:
- Swagger UI: `https://<server>/api/docs`
- ReDoc: `https://<server>/api/redoc`

### Database Backup and Restore

```bash
# Create backup
./web-monitoring.sh backup
# → backups/raidmonitor_YYYYMMDD_HHMMSS.sql.gz

# Restore from backup
./web-monitoring.sh restore backups/raidmonitor_20260226_120000.sql.gz
```

### File Structure

```
web_monitoring/
├── web-monitoring.sh          # Management script
├── docker-compose.yml         # Docker Compose configuration
├── .env                       # Secrets and settings (auto-generated)
├── Makefile                   # Build shortcuts
├── nginx/
│   ├── nginx.conf             # nginx configuration
│   └── ssl/                   # SSL certificates
│       ├── server.crt
│       └── server.key
├── server/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── entrypoint.sh
│   ├── app/                   # FastAPI application
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models/            # SQLAlchemy models
│   │   ├── api/v1/            # REST API endpoints
│   │   ├── web/               # Web routes (HTML)
│   │   ├── services/          # Business logic
│   │   ├── templates/         # Jinja2 templates
│   │   └── static/            # CSS, JS, vendor libs
│   ├── agent_packages/        # Uploaded agent RPMs
│   └── storcli_packages/      # Uploaded StorCLI RPMs
└── agent/                     # Agent source code
    ├── raid-agent.spec        # RPM build spec
    ├── setup.py
    ├── update-agent.sh        # Agent update script
    ├── config/                # Service and config templates
    └── raid_agent/            # Python package
```

### Troubleshooting

**Cannot access web UI:**
```bash
./web-monitoring.sh status          # Check all containers running
docker compose logs nginx           # Check nginx logs
docker compose logs web             # Check web app logs
```

**Database connection error:**
```bash
docker compose logs db              # Check PostgreSQL logs
docker compose restart db web       # Restart DB and web
```

**Agent not appearing on dashboard:**
- Check agent is registered: `cat /etc/raid-agent/config.yml` (api_key should be non-empty)
- Check agent service: `systemctl status raid-agent`
- Check agent logs: `journalctl -u raid-agent -f`
- Check network: `curl -sk https://<server>/api/v1/health`

---

<a id="russian"></a>

## Русский

### Требования

| Компонент | Минимум |
|-----------|---------|
| ОС | Любой Linux с поддержкой Docker |
| Docker | 20.10+ с Docker Compose v2 |
| ОЗУ | 2 ГБ (10 серверов) / 4 ГБ (50) / 8 ГБ (100+) |
| Диск | 5 ГБ (10 серверов) / 20 ГБ (50) / 50 ГБ (100+) |
| CPU | 1-4 vCPU в зависимости от нагрузки |
| Сеть | Порт 443 (HTTPS) открыт для агентов |

### Шаг 1. Установить Docker

**RHEL/CentOS 8/9:**

```bash
dnf install -y dnf-plugins-core
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
```

**Ubuntu/Debian:**

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Проверка:

```bash
docker --version
docker compose version
```

### Шаг 2. Клонировать репозиторий

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
```

### Шаг 3. Установить

```bash
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

Что произойдёт:
1. Генерация `.env` файла с секретами (пароль БД, JWT секрет, ключ шифрования)
2. Генерация самоподписанного SSL-сертификата
3. Сборка Docker-образов (nginx, веб-приложение, PostgreSQL)
4. Запуск всех контейнеров
5. Создание пользователя admin
6. Вывод учётных данных в терминале

**Сохраните пароль admin** — он отображается в терминале и записывается в файл `.env`.

### Шаг 4. Открыть веб-интерфейс

Откройте в браузере: `https://<ip-сервера>`

Войдите с учётными данными из шага 3.

### Настройка прокси (опционально)

Если серверу нужен прокси для скачивания Docker-образов при сборке:

```bash
./web-monitoring.sh proxy set socks5://proxy.example.com:1080
./web-monitoring.sh install
```

Удаление прокси:

```bash
./web-monitoring.sh proxy remove
```

### Команды управления

| Команда | Описание |
|---------|----------|
| `./web-monitoring.sh install` | Первичная установка (сборка + запуск) |
| `./web-monitoring.sh update` | Обновление (git pull + пересборка + перезапуск) |
| `./web-monitoring.sh reinstall` | Переустановка контейнеров (БД сохраняется) |
| `./web-monitoring.sh purge` | Полная переустановка (БД удаляется!) |
| `./web-monitoring.sh status` | Статус сервисов |
| `./web-monitoring.sh logs` | Все логи |
| `./web-monitoring.sh logs web` | Логи веб-приложения |
| `./web-monitoring.sh backup` | Бэкап базы данных PostgreSQL |
| `./web-monitoring.sh restore <файл>` | Восстановление БД из бэкапа |
| `./web-monitoring.sh proxy set <url>` | Установить прокси для сборки |
| `./web-monitoring.sh proxy remove` | Удалить прокси |

### Настройка SSL-сертификата

#### Самоподписанный (по умолчанию)

Создаётся автоматически при первом запуске. Агенты должны использовать `ssl_verify: false` в конфиге.

#### Свой сертификат (через веб)

1. Перейдите в **Настройки → SSL**
2. Загрузите сертификат (`.crt` / `.pem`) и приватный ключ (`.key`)
3. Система проверит соответствие сертификата и ключа
4. nginx перезагрузится автоматически

#### Свой сертификат (вручную)

Разместите файлы:
- `nginx/ssl/server.crt` — сертификат (PEM формат)
- `nginx/ssl/server.key` — приватный ключ (PEM формат)

Перезапустите nginx:

```bash
docker compose restart nginx
```

### LDAP / Active Directory

1. Перейдите в **Настройки → LDAP**
2. Заполните параметры подключения:
   - **URL сервера**: `ldap://dc.example.com` или `ldaps://dc.example.com:636`
   - **Bind DN**: `CN=svc_raid,OU=Service,DC=example,DC=com`
   - **Пароль Bind**: пароль сервисной учётной записи
   - **Search Base**: `OU=Users,DC=example,DC=com`
   - **Фильтр пользователей**: `(sAMAccountName={username})` (для AD)
   - **Группа администраторов**: `CN=RAID-Admins,OU=Groups,DC=example,DC=com` (опционально)
3. Нажмите **Проверить подключение**
4. Включите LDAP-аутентификацию

> Когда LDAP включён и существуют LDAP-администраторы, локальная учётная запись `admin` автоматически отключается. Для временного включения установите `ADMIN_FORCE_ENABLE=true` в `.env` и перезапустите. Отключится автоматически через 3 часа.

### Уведомления в Telegram

1. Создайте бота через [@BotFather](https://t.me/BotFather) и получите токен
2. Узнайте ID чата (отправьте сообщение [@userinfobot](https://t.me/userinfobot))
3. Перейдите в **Настройки → Telegram**
4. Введите токен бота и ID чата
5. Нажмите **Отправить тестовое сообщение**
6. Включите уведомления

### Загрузка пакета агента

Для автоустановки/автообновления агентов с сервера:

1. Перейдите в **Настройки → Агенты**
2. Загрузите файл `raid-agent-*.rpm` в разделе "Пакет агента"
3. Агенты будут проверять обновления и скачивать автоматически

### Загрузка пакета StorCLI

Если агентам нужна автоустановка storcli64:

1. Перейдите в **Настройки → Агенты**
2. Загрузите файл `storcli64-*.rpm` в разделе "Пакет StorCLI"
3. Агенты без storcli64 скачают и установят его автоматически

### Документация API

Установите `DEBUG=true` в `.env` и перезапустите:

```bash
vi .env
./web-monitoring.sh reinstall
```

Документация API:
- Swagger UI: `https://<сервер>/api/docs`
- ReDoc: `https://<сервер>/api/redoc`

### Бэкап и восстановление

```bash
# Создать бэкап
./web-monitoring.sh backup
# → backups/raidmonitor_YYYYMMDD_HHMMSS.sql.gz

# Восстановить из бэкапа
./web-monitoring.sh restore backups/raidmonitor_20260226_120000.sql.gz
```

### Структура файлов

```
web_monitoring/
├── web-monitoring.sh          # Скрипт управления
├── docker-compose.yml         # Docker Compose конфигурация
├── .env                       # Секреты и настройки (авто-генерация)
├── Makefile                   # Ярлыки сборки
├── nginx/
│   ├── nginx.conf             # Конфигурация nginx
│   └── ssl/                   # SSL-сертификаты
│       ├── server.crt
│       └── server.key
├── server/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── entrypoint.sh
│   ├── app/                   # Приложение FastAPI
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models/            # SQLAlchemy модели
│   │   ├── api/v1/            # REST API эндпоинты
│   │   ├── web/               # Веб-маршруты (HTML)
│   │   ├── services/          # Бизнес-логика
│   │   ├── templates/         # Jinja2 шаблоны
│   │   └── static/            # CSS, JS, вендорные библиотеки
│   ├── agent_packages/        # Загруженные RPM агентов
│   └── storcli_packages/      # Загруженные RPM StorCLI
└── agent/                     # Исходный код агента
    ├── raid-agent.spec        # RPM build спецификация
    ├── setup.py
    ├── update-agent.sh        # Скрипт обновления агента
    ├── config/                # Шаблоны сервиса и конфига
    └── raid_agent/            # Python-пакет
```

### Диагностика проблем

**Веб-интерфейс недоступен:**
```bash
./web-monitoring.sh status          # Проверить что все контейнеры запущены
docker compose logs nginx           # Логи nginx
docker compose logs web             # Логи веб-приложения
```

**Ошибка подключения к БД:**
```bash
docker compose logs db              # Логи PostgreSQL
docker compose restart db web       # Перезапустить БД и веб
```

**Агент не появляется на Dashboard:**
- Проверьте регистрацию: `cat /etc/raid-agent/config.yml` (api_key не пустой)
- Проверьте сервис: `systemctl status raid-agent`
- Проверьте логи: `journalctl -u raid-agent -f`
- Проверьте сеть: `curl -sk https://<сервер>/api/v1/health`
