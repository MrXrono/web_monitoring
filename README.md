# RAID Monitor

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## RAID Controller Monitoring System

Web-based monitoring for Broadcom/LSI MegaRAID controllers via `storcli64`. Docker web server + lightweight RPM agents on monitored servers.

### Key Features

- Real-time monitoring: controllers, virtual drives, physical drives, BBU/CacheVault
- SMART data collection with historical charts
- 28 built-in alert rules + Telegram notifications
- LDAP/Active Directory authentication
- SSL/TLS with certificate management via web UI
- Agent auto-update and auto-install of storcli64
- Bilingual UI (Russian / English), dark theme, mobile responsive

### Architecture

```
  Docker Host
  ┌──────────────────────────────────────┐
  │  nginx :443 → FastAPI → PostgreSQL   │
  └──────────────────────────────────────┘
        ↑ HTTPS            ↑ HTTPS
   ┌─────────┐       ┌─────────┐
   │ Agent 1  │  ...  │ Agent N  │
   └─────────┘       └─────────┘
```

### Quick Start — Server

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

Admin credentials are shown in the terminal and saved to `.env`.
Open `https://<server-ip>` in your browser.

### Quick Start — Agent

**Option A** — download from server and install:

```bash
curl -sk https://<server>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm
rpm -ivh /tmp/raid-agent.rpm
sed -i 's|https://raid-monitor.example.com|https://<server>|' /etc/raid-agent/config.yml
raid-agent --register
systemctl enable --now raid-agent
```

**Option B** — copy RPM manually:

```bash
scp raid-agent-*.rpm root@target:/tmp/
ssh root@target 'rpm -ivh /tmp/raid-agent-*.rpm'
```

Then configure and start:

```bash
vi /etc/raid-agent/config.yml   # set server_url
raid-agent --register
systemctl enable --now raid-agent
```

### Agent Update

```bash
curl -sk https://<server>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -U --force /tmp/raid-agent.rpm && systemctl restart raid-agent
```

Or use the bundled script: `bash update-agent.sh https://<server>`

### Management

```bash
./web-monitoring.sh install      # Build and start
./web-monitoring.sh update       # Pull, rebuild, restart
./web-monitoring.sh status       # Service status
./web-monitoring.sh logs [web]   # View logs
./web-monitoring.sh backup       # Backup database
./web-monitoring.sh restore <f>  # Restore from backup
```

### Documentation

Full setup guides are available in the **[docs](docs/)** folder:

- [Server Installation](docs/Server-Installation.md)
- [Agent Installation](docs/Agent-Installation.md)
- [Configuration Reference](docs/Configuration-Reference.md)

### Tech Stack

**Server:** Python 3.11, FastAPI, SQLAlchemy 2.0, PostgreSQL 16, nginx, Docker Compose
**Frontend:** Jinja2, Bootstrap 5, HTMX, Alpine.js, Chart.js
**Agent:** Python 3.9+, RPM, systemd, SELinux

---

<a id="russian"></a>

## Система мониторинга RAID-контроллеров

Веб-мониторинг RAID-контроллеров Broadcom/LSI MegaRAID через `storcli64`. Docker веб-сервер + легковесные RPM-агенты на контролируемых серверах.

### Основные возможности

- Мониторинг в реальном времени: контроллеры, виртуальные массивы, физические диски, BBU/CacheVault
- Сбор данных SMART с графиками истории
- 28 встроенных правил алертов + уведомления в Telegram
- Аутентификация LDAP/Active Directory
- SSL/TLS с управлением сертификатами через веб
- Автообновление агентов и автоустановка storcli64
- Двуязычный интерфейс (русский / английский), тёмная тема, мобильная адаптация

### Архитектура

```
  Docker Host
  ┌──────────────────────────────────────┐
  │  nginx :443 → FastAPI → PostgreSQL   │
  └──────────────────────────────────────┘
        ↑ HTTPS            ↑ HTTPS
   ┌─────────┐       ┌─────────┐
   │ Агент 1  │  ...  │ Агент N  │
   └─────────┘       └─────────┘
```

### Быстрый старт — Сервер

```bash
git clone https://github.com/MrXrono/web_monitoring.git
cd web_monitoring
chmod +x web-monitoring.sh
./web-monitoring.sh install
```

Пароль admin выводится в терминале и сохраняется в `.env`.
Откройте `https://<ip-сервера>` в браузере.

### Быстрый старт — Агент

**Вариант А** — скачать с сервера и установить:

```bash
curl -sk https://<сервер>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm
rpm -ivh /tmp/raid-agent.rpm
sed -i 's|https://raid-monitor.example.com|https://<сервер>|' /etc/raid-agent/config.yml
raid-agent --register
systemctl enable --now raid-agent
```

**Вариант Б** — скопировать RPM вручную:

```bash
scp raid-agent-*.rpm root@target:/tmp/
ssh root@target 'rpm -ivh /tmp/raid-agent-*.rpm'
```

Затем настроить и запустить:

```bash
vi /etc/raid-agent/config.yml   # указать server_url
raid-agent --register
systemctl enable --now raid-agent
```

### Обновление агента

```bash
curl -sk https://<сервер>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -U --force /tmp/raid-agent.rpm && systemctl restart raid-agent
```

Или скрипт: `bash update-agent.sh https://<сервер>`

### Управление

```bash
./web-monitoring.sh install      # Сборка и запуск
./web-monitoring.sh update       # Обновление (pull + пересборка)
./web-monitoring.sh status       # Статус сервисов
./web-monitoring.sh logs [web]   # Просмотр логов
./web-monitoring.sh backup       # Бэкап базы данных
./web-monitoring.sh restore <f>  # Восстановление из бэкапа
```

### Документация

Подробные инструкции доступны в папке **[docs](docs/)**:

- [Установка сервера](docs/Server-Installation.md)
- [Установка агента](docs/Agent-Installation.md)
- [Справочник конфигурации](docs/Configuration-Reference.md)

### Стек технологий

**Сервер:** Python 3.11, FastAPI, SQLAlchemy 2.0, PostgreSQL 16, nginx, Docker Compose
**Фронтенд:** Jinja2, Bootstrap 5, HTMX, Alpine.js, Chart.js
**Агент:** Python 3.9+, RPM, systemd, SELinux

### Лицензия

MIT License
