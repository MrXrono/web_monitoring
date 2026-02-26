# RAID Monitor — Documentation

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## English

Welcome to the RAID Monitor documentation. This section contains detailed guides for installing, configuring, and managing the RAID monitoring system.

### Pages

| Page | Description |
|------|-------------|
| [Server Installation](Server-Installation.md) | Installing and configuring the web server (Docker) |
| [Agent Installation](Agent-Installation.md) | Installing and configuring agents on monitored servers |
| [Configuration Reference](Configuration-Reference.md) | All configuration parameters for server and agent |

### Overview

RAID Monitor consists of two components:

1. **Web Server** — Docker-based application (nginx + FastAPI + PostgreSQL) that receives data from agents, stores it, and provides a web interface.
2. **Agent** — lightweight daemon (RPM package) installed on each server with a MegaRAID controller. Collects RAID data via `storcli64` and reports to the web server.

### Data Flow

```
Agent (every 10 min)                    Web Server (Docker)
┌──────────────────┐                    ┌──────────────────┐
│ 1. storcli64     │  POST /report      │ FastAPI          │
│ 2. collect data  │ ──────────────────>│ process + store  │
│ 3. send report   │                    │ PostgreSQL       │
│                  │  GET /commands      │                  │
│ 4. poll commands │ <─────────────────>│ pending_commands │
└──────────────────┘                    └──────────────────┘
                                               │
                                         Web UI (HTTPS)
                                               │
                                        ┌──────┴──────┐
                                        │  Dashboard  │
                                        │  Alerts     │
                                        │  Settings   │
                                        └─────────────┘
```

---

<a id="russian"></a>

## Русский

Добро пожаловать в документацию RAID Monitor. Здесь содержатся подробные руководства по установке, настройке и управлению системой мониторинга RAID.

### Страницы

| Страница | Описание |
|----------|----------|
| [Установка сервера (Server Installation)](Server-Installation.md) | Установка и настройка веб-сервера (Docker) |
| [Установка агента (Agent Installation)](Agent-Installation.md) | Установка и настройка агентов на контролируемых серверах |
| [Справочник конфигурации (Configuration Reference)](Configuration-Reference.md) | Все параметры конфигурации сервера и агента |

### Обзор

RAID Monitor состоит из двух компонентов:

1. **Веб-сервер** — приложение в Docker (nginx + FastAPI + PostgreSQL), принимает данные от агентов, хранит их и предоставляет веб-интерфейс.
2. **Агент** — легковесный демон (RPM-пакет), устанавливается на каждом сервере с контроллером MegaRAID. Собирает данные RAID через `storcli64` и отправляет на веб-сервер.

### Поток данных

```
Агент (каждые 10 мин)                  Веб-сервер (Docker)
┌──────────────────┐                    ┌──────────────────┐
│ 1. storcli64     │  POST /report      │ FastAPI          │
│ 2. сбор данных   │ ──────────────────>│ обработка + БД   │
│ 3. отправка      │                    │ PostgreSQL       │
│                  │  GET /commands      │                  │
│ 4. опрос команд  │ <─────────────────>│ pending_commands │
└──────────────────┘                    └──────────────────┘
                                               │
                                         Веб UI (HTTPS)
                                               │
                                        ┌──────┴──────┐
                                        │  Dashboard  │
                                        │  Алерты     │
                                        │  Настройки  │
                                        └─────────────┘
```
