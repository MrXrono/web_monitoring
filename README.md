# RAID Monitor

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## RAID Controller Monitoring System

A web-based monitoring system for hardware RAID controllers (Broadcom/LSI MegaRAID) using the `storcli64` utility. Consists of a web server (Docker) and lightweight agents installed on monitored servers.

### Features

- **Real-time monitoring** of RAID controllers, virtual drives, physical drives, and BBU/CacheVault
- **SMART data collection** with historical trends and charts
- **28 built-in alert rules** covering VD degradation, PD failures, temperature, SMART errors, BBU state, agent connectivity
- **Telegram notifications** for critical alerts
- **LDAP/Active Directory** authentication
- **SSL/TLS** — nginx reverse proxy with certificate management via web UI
- **Agent auto-update** — push new versions from web server
- **SELinux** policies for the agent
- **Bilingual UI** — Russian and English
- **Mobile responsive** design
- **Debug logging** — toggleable for web server and individual agents
- **Log collection** — collect agent logs and upload to file server
- **Data retention** — automatic cleanup of old SMART history and events

### Architecture

```
┌─────────────────────────────────────────────┐
│              Docker Host                     │
│                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
│  │  nginx   │→│  FastAPI  │→│ PostgreSQL  │  │
│  │  :443    │  │  :8000   │  │  :5432     │  │
│  └─────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────┘
        ↑               ↑
        │  HTTPS/443     │
   ┌────┴────┐    ┌──────┴──────┐
   │ Agent 1 │    │  Agent N    │
   │ Server1 │    │  ServerN    │
   └─────────┘    └─────────────┘
```

### Requirements

#### Web Server
- Docker 20.10+ with Docker Compose v2
- 2-8 GB RAM (depending on number of agents)
- 5-50 GB disk

| Servers | CPU   | RAM  | Disk  |
|---------|-------|------|-------|
| 10      | 1 vCPU | 2 GB | 5 GB  |
| 50      | 2 vCPU | 4 GB | 20 GB |
| 100+    | 4 vCPU | 8 GB | 50 GB |

#### Agent
- RHEL/CentOS 7/8/9 or compatible (x86_64)
- Python 3.9+
- Root access (for storcli64)
- Network access to web server (port 443)

### Quick Start

#### 1. Install Web Server

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

On first start:
- `.env` file is generated with random secrets
- Self-signed SSL certificate is created
- Admin user is created (credentials shown in terminal and saved to `.env`)

Access: `https://<your-server-ip>`

#### 2. Install Agent

Copy the agent RPM to the target server and install:

```bash
rpm -ivh raid-agent-1.0.0-1.x86_64.rpm
```

Edit the configuration:

```bash
vi /etc/raid-agent/config.yml
```

Set the web server URL:

```yaml
server_url: "https://raid-monitor.example.com"
```

Start the agent:

```bash
systemctl enable --now raid-agent
```

The agent will:
1. Register with the web server and receive an API key
2. Auto-detect or install `storcli64`
3. Collect RAID data and send it to the web server
4. Repeat every 10 minutes

### Management Script

```bash
./web-monitoring.sh install      # Install (build + start)
./web-monitoring.sh update       # Update (pull + rebuild + restart)
./web-monitoring.sh reinstall    # Reinstall (keep database)
./web-monitoring.sh purge        # Full reinstall (delete database)
./web-monitoring.sh status       # Service status
./web-monitoring.sh logs [web]   # View logs
./web-monitoring.sh backup       # Backup database
./web-monitoring.sh restore <f>  # Restore from backup
```

### Web UI Structure

- **Dashboard** — overview of all servers with status cards, filters, search
- **Server Detail** — 6 tabs: Overview, Controllers, Virtual Drives, Physical Drives, Events, Agent
- **Alerts** — active alerts, history, 28 configurable rules
- **Settings** — General, LDAP, Telegram, SSL, Agent Packages, Debug

### Alert Rules

| Category        | Rules | Examples |
|-----------------|-------|---------|
| Virtual Drive   | 6     | VD Degraded, VD Offline, VD Rebuilding |
| Physical Drive  | 11    | PD Failed, SMART Alert, Temperature >55°C, Media Errors |
| Controller      | 4     | Status Not OK, ROC Temperature >80°C, Memory Errors |
| BBU/CacheVault  | 4     | Not Optimal, Replacement Needed |
| Agent           | 3     | Offline >20min, Outdated Version |

### Agent Configuration

`/etc/raid-agent/config.yml`:

```yaml
server_url: "https://raid-monitor.example.com"
api_key: ""                    # Auto-populated after registration
storcli_path: "/opt/MegaRAID/storcli/storcli64"
collection_interval: 600      # 10 minutes
ssl_verify: true
ca_bundle: ""                  # Custom CA bundle (optional)
debug: false
log_file: "/var/log/raid-agent/agent.log"
```

### SSL Certificate

By default, a self-signed certificate is generated. To use your own:

1. Via Web UI: Settings → SSL → Upload Certificate
2. Or manually place files in `nginx/ssl/server.crt` and `nginx/ssl/server.key`

### LDAP Configuration

1. Go to Settings → LDAP
2. Enter your LDAP/AD server details
3. Click "Test Connection"
4. Enable LDAP authentication
5. After adding LDAP admins, the local admin account is automatically disabled

To temporarily re-enable local admin, set `ADMIN_FORCE_ENABLE=true` in `.env` file. It will be disabled automatically after 3 hours.

### Telegram Alerts

1. Create a Telegram bot via @BotFather
2. Get the bot token and chat ID
3. Go to Settings → Telegram
4. Enter token and chat ID
5. Click "Send Test Message" to verify
6. Enable notifications

### API Documentation

When DEBUG=true in `.env`, API docs are available at:
- Swagger UI: `https://<server>/api/docs`
- ReDoc: `https://<server>/api/redoc`

### Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy 2.0, PostgreSQL 16
- **Frontend**: Jinja2, Bootstrap 5, HTMX, Alpine.js, Chart.js
- **Infrastructure**: Docker Compose, nginx, systemd
- **Agent**: Python 3.9+, RPM packaging, SELinux

---

<a id="russian"></a>

## Система мониторинга RAID-контроллеров

Веб-система мониторинга аппаратных RAID-контроллеров (Broadcom/LSI MegaRAID) через утилиту `storcli64`. Состоит из веб-сервера (Docker) и агентов на мониторируемых серверах.

### Возможности

- **Мониторинг в реальном времени** RAID-контроллеров, виртуальных массивов, физических дисков и BBU/CacheVault
- **Сбор данных SMART** с историей и графиками трендов
- **28 встроенных правил алертов** — деградация VD, отказ PD, температура, SMART ошибки, BBU, связь агента
- **Уведомления в Telegram** для критических алертов
- **LDAP/Active Directory** аутентификация
- **SSL/TLS** — nginx reverse proxy с управлением сертификатами через веб
- **Автообновление агентов** — push новых версий с веб-сервера
- **SELinux** политики для агента
- **Двуязычный интерфейс** — русский и английский
- **Мобильная адаптация** — responsive дизайн
- **Debug логирование** — включается для веба и отдельных агентов
- **Сбор логов** — сбор логов агентов и загрузка на файл-сервер
- **Ретенция данных** — автоочистка старых данных SMART и событий

### Архитектура

```
┌─────────────────────────────────────────────┐
│              Docker Host                     │
│                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
│  │  nginx   │→│  FastAPI  │→│ PostgreSQL  │  │
│  │  :443    │  │  :8000   │  │  :5432     │  │
│  └─────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────┘
        ↑               ↑
        │  HTTPS/443     │
   ┌────┴────┐    ┌──────┴──────┐
   │ Агент 1 │    │  Агент N    │
   │ Сервер1 │    │  СерверN    │
   └─────────┘    └─────────────┘
```

### Требования

#### Веб-сервер
- Docker 20.10+ с Docker Compose v2
- 2-8 ГБ ОЗУ (в зависимости от количества агентов)
- 5-50 ГБ диска

| Серверы | CPU    | ОЗУ   | Диск   |
|---------|--------|-------|--------|
| 10      | 1 vCPU | 2 ГБ  | 5 ГБ   |
| 50      | 2 vCPU | 4 ГБ  | 20 ГБ  |
| 100+    | 4 vCPU | 8 ГБ  | 50 ГБ  |

#### Агент
- RHEL/CentOS 7/8/9 или совместимые (x86_64)
- Python 3.9+
- Root-доступ (для storcli64)
- Сетевой доступ к веб-серверу (порт 443)

### Быстрый старт

#### 1. Установка веб-сервера

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

При первом запуске:
- Генерируется файл `.env` с случайными секретами
- Создаётся самоподписанный SSL-сертификат
- Создаётся пользователь admin (данные для входа в терминале и в `.env`)

Доступ: `https://<ip-сервера>`

#### 2. Установка агента

Скопируйте RPM на целевой сервер и установите:

```bash
rpm -ivh raid-agent-1.0.0-1.x86_64.rpm
```

Отредактируйте конфигурацию:

```bash
vi /etc/raid-agent/config.yml
```

Укажите URL веб-сервера:

```yaml
server_url: "https://raid-monitor.example.com"
```

Запустите агент:

```bash
systemctl enable --now raid-agent
```

Агент:
1. Зарегистрируется на веб-сервере и получит API-ключ
2. Найдёт или установит `storcli64`
3. Соберёт данные RAID и отправит на веб-сервер
4. Будет повторять каждые 10 минут

### Скрипт управления

```bash
./web-monitoring.sh install      # Установка (сборка + запуск)
./web-monitoring.sh update       # Обновление (pull + пересборка + перезапуск)
./web-monitoring.sh reinstall    # Переустановка (с сохранением БД)
./web-monitoring.sh purge        # Полная переустановка (удаление БД)
./web-monitoring.sh status       # Статус сервисов
./web-monitoring.sh logs [web]   # Просмотр логов
./web-monitoring.sh backup       # Бэкап базы данных
./web-monitoring.sh restore <f>  # Восстановление из бэкапа
```

### Структура веб-интерфейса

- **Панель управления** — обзор всех серверов, карточки статуса, фильтры, поиск
- **Детали сервера** — 6 вкладок: Обзор, Контроллеры, Виртуальные массивы, Физические диски, События, Агент
- **Алерты** — активные алерты, история, 28 настраиваемых правил
- **Настройки** — Общие, LDAP, Telegram, SSL, Пакеты агента, Отладка

### Правила алертов

| Категория         | Кол-во | Примеры |
|-------------------|--------|---------|
| Виртуальные массивы | 6    | VD Degraded, VD Offline, VD Rebuilding |
| Физические диски   | 11    | PD Failed, SMART Alert, Температура >55°C, Media Errors |
| Контроллер         | 4     | Status Not OK, ROC Температура >80°C, Memory Errors |
| BBU/CacheVault     | 4     | Not Optimal, Требуется замена |
| Агент              | 3     | Offline >20 мин, Устаревшая версия |

### Конфигурация агента

`/etc/raid-agent/config.yml`:

```yaml
server_url: "https://raid-monitor.example.com"
api_key: ""                    # Заполняется автоматически после регистрации
storcli_path: "/opt/MegaRAID/storcli/storcli64"
collection_interval: 600      # 10 минут
ssl_verify: true
ca_bundle: ""                  # Путь к CA bundle (опционально)
debug: false
log_file: "/var/log/raid-agent/agent.log"
```

### SSL-сертификат

По умолчанию создаётся самоподписанный сертификат. Для использования своего:

1. Через веб: Настройки → SSL → Загрузить сертификат
2. Или вручную: `nginx/ssl/server.crt` и `nginx/ssl/server.key`

### Настройка LDAP

1. Перейдите в Настройки → LDAP
2. Введите данные LDAP/AD сервера
3. Нажмите "Проверить подключение"
4. Включите LDAP аутентификацию
5. После добавления LDAP-администраторов локальная УЗ admin отключается

Для временного включения локального админа установите `ADMIN_FORCE_ENABLE=true` в `.env`. Будет отключён автоматически через 3 часа.

### Telegram уведомления

1. Создайте бота через @BotFather
2. Получите токен бота и ID чата
3. Перейдите в Настройки → Telegram
4. Введите токен и ID чата
5. Нажмите "Отправить тестовое сообщение"
6. Включите уведомления

### Документация API

При DEBUG=true в `.env` доступна документация:
- Swagger UI: `https://<сервер>/api/docs`
- ReDoc: `https://<сервер>/api/redoc`

### Стек технологий

- **Backend**: Python 3.11, FastAPI, SQLAlchemy 2.0, PostgreSQL 16
- **Frontend**: Jinja2, Bootstrap 5, HTMX, Alpine.js, Chart.js
- **Инфраструктура**: Docker Compose, nginx, systemd
- **Агент**: Python 3.9+, RPM пакет, SELinux

### Лицензия

MIT License
