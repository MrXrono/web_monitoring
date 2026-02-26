# Configuration Reference / Справочник конфигурации

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## English

### Server Configuration (`.env`)

The `.env` file is auto-generated on first start. Location: project root directory.

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `raidmonitor` | PostgreSQL database name |
| `POSTGRES_USER` | `raidmonitor` | PostgreSQL username |
| `POSTGRES_PASSWORD` | *(generated)* | PostgreSQL password |
| `SECRET_KEY` | *(generated)* | JWT signing key |
| `ENCRYPTION_KEY` | *(generated)* | Encryption key for sensitive settings |
| `ADMIN_PASSWORD` | *(generated)* | Initial admin password |
| `ADMIN_FORCE_ENABLE` | `false` | Force-enable local admin (auto-disables after 3h) |
| `DEBUG` | `false` | Enable debug mode (API docs, verbose logging) |
| `LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `APP_HOST` | `0.0.0.0` | Application bind host |
| `APP_PORT` | `8000` | Application bind port |
| `TELEGRAM_BOT_TOKEN_ENCRYPTED` | *(empty)* | Encrypted Telegram bot token |
| `TELEGRAM_CHAT_ID` | *(empty)* | Telegram chat ID |

### Agent Configuration (`/etc/raid-agent/config.yml`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server_url` | string | `https://raid-monitor.example.com` | **Required.** URL of the monitoring server |
| `api_key` | string | *(empty)* | API key for authentication (auto-set after registration) |
| `storcli_path` | string | `/opt/MegaRAID/storcli/storcli64` | Path to storcli64 binary. Leave empty for auto-detection |
| `collection_interval` | integer | `600` | Data collection interval in seconds (10 minutes) |
| `ssl_verify` | boolean | `true` | Verify SSL certificate. Set `false` for self-signed certs |
| `ca_bundle` | string | *(empty)* | Path to custom CA bundle file for SSL verification |
| `debug` | boolean | `false` | Enable debug logging |
| `log_file` | string | `/var/log/raid-agent/agent.log` | Log file path |
| `log_max_size` | integer | `10485760` | Max log file size in bytes (10 MB) |
| `log_backup_count` | integer | `5` | Number of rotated log files to keep |

### Full Config Example

```yaml
# RAID Monitor Agent Configuration

# Server URL (required)
server_url: "https://raid-monitor.example.com"

# API Key (auto-populated after registration)
api_key: ""

# Path to storcli64 binary (auto-detected if empty)
storcli_path: "/opt/MegaRAID/storcli/storcli64"

# Collection interval in seconds (default: 600 = 10 minutes)
collection_interval: 600

# SSL certificate verification (set to false for self-signed certificates)
ssl_verify: true

# Custom CA bundle path (optional, empty = system default)
# Use this to specify a custom CA certificate for self-signed server certs:
# ca_bundle: "/etc/raid-agent/server-ca.pem"
ca_bundle: ""

# Debug logging
debug: false

# Log settings
log_file: "/var/log/raid-agent/agent.log"
log_max_size: 10485760
log_backup_count: 5
```

### Web UI Settings

These are configured via the web interface at **Settings** page:

#### General

| Setting | Description |
|---------|-------------|
| Default Language | Interface language (en/ru) |
| Data Retention | Days to keep SMART history and events (default: 90) |
| Agent Auto-Approve | Automatically approve new agent registrations |

#### LDAP

| Setting | Description |
|---------|-------------|
| Enabled | Enable/disable LDAP authentication |
| Server URL | `ldap://` or `ldaps://` URL |
| Bind DN | Distinguished Name for LDAP bind |
| Bind Password | Password for LDAP bind (stored encrypted) |
| Search Base | Base DN for user searches |
| User Filter | LDAP filter template, e.g. `(sAMAccountName={username})` |
| Group Filter | Optional group membership filter |
| Admin Group | DN of the admin group |

#### Telegram

| Setting | Description |
|---------|-------------|
| Enabled | Enable/disable Telegram notifications |
| Bot Token | Token from @BotFather (stored encrypted) |
| Chat ID | Telegram chat or group ID |

#### SSL

| Setting | Description |
|---------|-------------|
| Certificate | PEM-format SSL certificate |
| Private Key | PEM-format private key (must match the certificate) |

#### Debug

| Setting | Description |
|---------|-------------|
| Web Debug | Enable verbose logging for the web application |
| Agent Debug | Toggle debug mode for individual agents |

### Alert Rules

28 built-in rules organized by category:

| # | Rule | Severity | Description |
|---|------|----------|-------------|
| **Virtual Drives** | | | |
| 1 | VD Degraded | critical | Virtual drive is in Degraded state |
| 2 | VD Offline | critical | Virtual drive is Offline |
| 3 | VD Partially Degraded | warning | Virtual drive is partially degraded |
| 4 | VD Rebuilding | warning | Virtual drive is rebuilding |
| 5 | VD Initialization | info | Virtual drive is initializing |
| 6 | VD Cache Policy | info | Write cache policy not optimal |
| **Physical Drives** | | | |
| 7 | PD Failed | critical | Physical drive failed |
| 8 | PD Predictive Failure | warning | SMART predicts failure |
| 9 | PD SMART Alert | warning | SMART attribute flagged |
| 10 | PD Temperature High | warning | Temperature > 55°C |
| 11 | PD Temperature Critical | critical | Temperature > 65°C |
| 12 | PD Media Errors | warning | Media error count exceeded threshold |
| 13 | PD Other Errors | warning | Other error count exceeded threshold |
| 14 | PD Predictive Errors | info | Predictive failure count > 0 |
| 15 | PD Not Online | warning | Physical drive not in Online state |
| 16 | PD SSD Wear | warning | SSD wear level threshold |
| 17 | PD Foreign | info | Foreign drive detected |
| **Controllers** | | | |
| 18 | Controller Not Optimal | critical | Controller status is not Optimal |
| 19 | ROC Temp High | warning | ROC temperature > 80°C |
| 20 | ROC Temp Critical | critical | ROC temperature > 95°C |
| 21 | Memory Errors | warning | Uncorrectable memory errors detected |
| **BBU/CacheVault** | | | |
| 22 | BBU Not Optimal | warning | BBU/CacheVault state not Optimal |
| 23 | BBU Replacement | critical | BBU replacement required |
| 24 | BBU Low Charge | warning | BBU charge below threshold |
| 25 | CacheVault Low Capacitance | warning | CacheVault capacitance below threshold |
| **Agent** | | | |
| 26 | Agent Offline | critical | Agent not reporting for > 20 minutes |
| 27 | Agent Outdated | info | Agent version is not current |
| 28 | Agent Error | warning | Agent reporting errors |

### API Endpoints

Base URL: `https://<server>/api/v1`

#### Agent API (authenticated with API key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/agent/register` | Register new agent (no auth) |
| POST | `/agent/report` | Send RAID data report |
| GET | `/agent/commands` | Poll for pending commands |
| POST | `/agent/commands/{id}/ack` | Acknowledge command execution |
| GET | `/agent/update/check` | Check for agent updates |
| GET | `/agent/update/download` | Download agent RPM |
| GET | `/agent/storcli/download` | Download storcli64 RPM |

#### Public API (no auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agent/package/latest` | Download latest agent RPM |
| GET | `/agent/package/version` | Get latest agent version info |
| GET | `/health` | Health check |

---

<a id="russian"></a>

## Русский

### Конфигурация сервера (`.env`)

Файл `.env` создаётся автоматически при первом запуске. Расположение: корневая директория проекта.

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `POSTGRES_DB` | `raidmonitor` | Имя базы данных PostgreSQL |
| `POSTGRES_USER` | `raidmonitor` | Имя пользователя PostgreSQL |
| `POSTGRES_PASSWORD` | *(генерируется)* | Пароль PostgreSQL |
| `SECRET_KEY` | *(генерируется)* | Ключ подписи JWT |
| `ENCRYPTION_KEY` | *(генерируется)* | Ключ шифрования для чувствительных настроек |
| `ADMIN_PASSWORD` | *(генерируется)* | Начальный пароль администратора |
| `ADMIN_FORCE_ENABLE` | `false` | Принудительно включить локального админа (отключается через 3ч) |
| `DEBUG` | `false` | Режим отладки (документация API, подробные логи) |
| `LOG_LEVEL` | `INFO` | Уровень логирования: DEBUG, INFO, WARNING, ERROR |
| `APP_HOST` | `0.0.0.0` | Хост привязки приложения |
| `APP_PORT` | `8000` | Порт привязки приложения |
| `TELEGRAM_BOT_TOKEN_ENCRYPTED` | *(пусто)* | Зашифрованный токен Telegram-бота |
| `TELEGRAM_CHAT_ID` | *(пусто)* | ID чата Telegram |

### Конфигурация агента (`/etc/raid-agent/config.yml`)

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `server_url` | строка | `https://raid-monitor.example.com` | **Обязательный.** URL сервера мониторинга |
| `api_key` | строка | *(пусто)* | API-ключ аутентификации (устанавливается после регистрации) |
| `storcli_path` | строка | `/opt/MegaRAID/storcli/storcli64` | Путь к storcli64. Пустое значение — автопоиск |
| `collection_interval` | число | `600` | Интервал сбора данных в секундах (10 минут) |
| `ssl_verify` | логическое | `true` | Проверка SSL-сертификата. `false` для самоподписанных |
| `ca_bundle` | строка | *(пусто)* | Путь к файлу CA bundle для проверки SSL |
| `debug` | логическое | `false` | Включить отладочное логирование |
| `log_file` | строка | `/var/log/raid-agent/agent.log` | Путь к файлу логов |
| `log_max_size` | число | `10485760` | Максимальный размер файла логов в байтах (10 МБ) |
| `log_backup_count` | число | `5` | Количество ротируемых файлов логов |

### Полный пример конфига

```yaml
# Конфигурация RAID Monitor Agent

# URL сервера (обязательно)
server_url: "https://raid-monitor.example.com"

# API-ключ (заполняется автоматически после регистрации)
api_key: ""

# Путь к storcli64 (автоопределение если пусто)
storcli_path: "/opt/MegaRAID/storcli/storcli64"

# Интервал сбора данных в секундах (по умолчанию: 600 = 10 минут)
collection_interval: 600

# Проверка SSL-сертификата (false для самоподписанных сертификатов)
ssl_verify: true

# Путь к CA bundle (опционально, пусто = системный)
ca_bundle: ""

# Режим отладки
debug: false

# Настройки логирования
log_file: "/var/log/raid-agent/agent.log"
log_max_size: 10485760
log_backup_count: 5
```

### Настройки веб-интерфейса

Настраиваются через веб на странице **Настройки**:

#### Общие

| Настройка | Описание |
|-----------|----------|
| Язык по умолчанию | Язык интерфейса (en/ru) |
| Ретенция данных | Дни хранения истории SMART и событий (по умолчанию: 90) |
| Автоодобрение агентов | Автоматически одобрять новые регистрации агентов |

#### LDAP

| Настройка | Описание |
|-----------|----------|
| Включён | Включить/выключить LDAP-аутентификацию |
| URL сервера | `ldap://` или `ldaps://` URL |
| Bind DN | Distinguished Name для LDAP bind |
| Пароль Bind | Пароль для LDAP bind (хранится зашифрованным) |
| Search Base | Базовый DN для поиска пользователей |
| Фильтр пользователей | Шаблон LDAP-фильтра, напр. `(sAMAccountName={username})` |
| Фильтр групп | Опциональный фильтр членства в группах |
| Группа администраторов | DN группы администраторов |

#### Telegram

| Настройка | Описание |
|-----------|----------|
| Включён | Включить/выключить уведомления Telegram |
| Токен бота | Токен от @BotFather (хранится зашифрованным) |
| ID чата | ID чата или группы Telegram |

#### SSL

| Настройка | Описание |
|-----------|----------|
| Сертификат | SSL-сертификат в формате PEM |
| Приватный ключ | Приватный ключ в формате PEM (должен соответствовать сертификату) |

#### Отладка

| Настройка | Описание |
|-----------|----------|
| Отладка веба | Включить подробное логирование для веб-приложения |
| Отладка агентов | Переключение режима отладки для отдельных агентов |

### Правила алертов

28 встроенных правил по категориям:

| # | Правило | Критичность | Описание |
|---|---------|-------------|----------|
| **Виртуальные массивы** | | | |
| 1 | VD Degraded | critical | Виртуальный массив в состоянии Degraded |
| 2 | VD Offline | critical | Виртуальный массив Offline |
| 3 | VD Partially Degraded | warning | Частичная деградация |
| 4 | VD Rebuilding | warning | Ребилд виртуального массива |
| 5 | VD Initialization | info | Инициализация |
| 6 | VD Cache Policy | info | Не оптимальная политика кэша |
| **Физические диски** | | | |
| 7 | PD Failed | critical | Диск вышел из строя |
| 8 | PD Predictive Failure | warning | SMART предсказывает отказ |
| 9 | PD SMART Alert | warning | SMART атрибут помечен |
| 10 | PD Temperature High | warning | Температура > 55°C |
| 11 | PD Temperature Critical | critical | Температура > 65°C |
| 12 | PD Media Errors | warning | Превышен порог ошибок чтения |
| 13 | PD Other Errors | warning | Превышен порог прочих ошибок |
| 14 | PD Predictive Errors | info | Предсказанные ошибки > 0 |
| 15 | PD Not Online | warning | Диск не в состоянии Online |
| 16 | PD SSD Wear | warning | Порог износа SSD |
| 17 | PD Foreign | info | Обнаружен чужой диск |
| **Контроллеры** | | | |
| 18 | Controller Not Optimal | critical | Статус контроллера не Optimal |
| 19 | ROC Temp High | warning | Температура ROC > 80°C |
| 20 | ROC Temp Critical | critical | Температура ROC > 95°C |
| 21 | Memory Errors | warning | Некорректируемые ошибки памяти |
| **BBU/CacheVault** | | | |
| 22 | BBU Not Optimal | warning | BBU/CacheVault не в состоянии Optimal |
| 23 | BBU Replacement | critical | Требуется замена BBU |
| 24 | BBU Low Charge | warning | Низкий заряд BBU |
| 25 | CacheVault Low Capacitance | warning | Низкая ёмкость CacheVault |
| **Агент** | | | |
| 26 | Agent Offline | critical | Агент не отвечает > 20 минут |
| 27 | Agent Outdated | info | Устаревшая версия агента |
| 28 | Agent Error | warning | Агент сообщает об ошибках |

### API-эндпоинты

Базовый URL: `https://<сервер>/api/v1`

#### Agent API (аутентификация по API-ключу)

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | `/agent/register` | Регистрация нового агента (без авторизации) |
| POST | `/agent/report` | Отправка отчёта с данными RAID |
| GET | `/agent/commands` | Опрос ожидающих команд |
| POST | `/agent/commands/{id}/ack` | Подтверждение выполнения команды |
| GET | `/agent/update/check` | Проверка обновлений агента |
| GET | `/agent/update/download` | Скачивание RPM агента |
| GET | `/agent/storcli/download` | Скачивание RPM storcli64 |

#### Публичные API (без авторизации)

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| GET | `/agent/package/latest` | Скачать последний RPM агента |
| GET | `/agent/package/version` | Получить информацию о версии |
| GET | `/health` | Проверка состояния |
