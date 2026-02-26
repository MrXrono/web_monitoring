# Agent Installation / Установка агента

**[English](#english) | [Русский](#russian)**

---

<a id="english"></a>

## English

### Requirements

| Component | Requirement |
|-----------|-------------|
| OS | RHEL / CentOS / Rocky / Alma Linux 7, 8, 9 (x86_64) |
| Python | 3.9+ |
| Access | root (required for storcli64) |
| Network | HTTPS access to the monitoring server (port 443) |
| RAID | Broadcom/LSI MegaRAID or Dell PERC controller |

### Installation Methods

#### Method 1: Download from Server (recommended)

```bash
curl -sk https://<server>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm
rpm -ivh /tmp/raid-agent.rpm
sed -i 's|https://raid-monitor.example.com|https://<server>|' /etc/raid-agent/config.yml
raid-agent --register
systemctl enable --now raid-agent
```

**One-liner:**

```bash
curl -sk https://<server>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -ivh /tmp/raid-agent.rpm && \
  sed -i 's|https://raid-monitor.example.com|https://<server>|' /etc/raid-agent/config.yml && \
  raid-agent --register && \
  systemctl enable --now raid-agent
```

#### Method 2: Copy RPM manually

```bash
# From admin machine
scp raid-agent-1.0.4-1.el8.noarch.rpm root@target-server:/tmp/

# On target server
rpm -ivh /tmp/raid-agent-1.0.4-1.el8.noarch.rpm
```

### Step-by-Step Setup

#### Step 1. Install RPM

```bash
rpm -ivh raid-agent-1.0.4-1.el8.noarch.rpm
```

The RPM installer automatically:
- Creates a Python virtualenv at `/opt/raid-agent/venv`
- Installs dependencies (`requests`, `pyyaml`)
- Creates symlink `/usr/local/bin/raid-agent`
- Installs systemd service `raid-agent.service`
- Creates config at `/etc/raid-agent/config.yml`
- Sets up log rotation (`/etc/logrotate.d/raid-agent`)
- Builds and installs SELinux policy (if available)

#### Step 2. Configure

Edit the configuration file:

```bash
vi /etc/raid-agent/config.yml
```

**Required:** Set the `server_url` to your monitoring server:

```yaml
server_url: "https://raid-monitor.example.com"
```

If the server uses a self-signed certificate:

```yaml
ssl_verify: false
```

Full config reference: [Configuration Reference](Configuration-Reference.md)

#### Step 3. Register

```bash
raid-agent --register
```

What happens:
1. Agent collects system information (hostname, IP, OS)
2. Sends `POST /api/v1/agent/register` to the server
3. Server creates a record and returns an API key
4. Agent saves the API key to `/etc/raid-agent/config.yml`

Expected output:
```
Registration successful!
Server ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
API key saved to /etc/raid-agent/config.yml
```

#### Step 4. Start the Service

```bash
systemctl enable --now raid-agent
```

Verify:
```bash
systemctl status raid-agent
```

The agent will:
1. Find or auto-install `storcli64`
2. Collect RAID data
3. Send the first report to the server
4. Repeat every 10 minutes
5. Poll for commands every 30 seconds

### StorCLI (storcli64)

The agent needs `storcli64` to collect RAID data. It searches automatically in:

| Path | Description |
|------|-------------|
| `/opt/MegaRAID/storcli/storcli64` | Standard MegaRAID location |
| `/opt/MegaRAID/storcli64/storcli64` | Alternative location |
| `/usr/local/bin/storcli64` | Local bin |
| `/usr/bin/storcli64` | System bin |
| `/usr/sbin/storcli64` | System sbin |
| `/opt/MegaRAID/perccli/perccli64` | Dell PERC (fallback) |
| `/opt/dell/perccli/perccli64` | Dell alternative |

**Auto-install from server:** If storcli64 is not found and the admin uploaded the RPM to Settings → Agents → StorCLI Package, the agent downloads and installs it automatically.

**Manual install:**

```bash
rpm -ivh storcli-007.2705.0000.0000-1.noarch.rpm
```

### Agent Update

#### Automatic

If the admin uploaded a newer agent RPM to Settings → Agents → Agent Package, the agent detects the update and installs it automatically.

#### Manual — via update script

```bash
bash /opt/raid-agent/update-agent.sh https://<server>
```

The script:
1. Checks the server for the latest version
2. Compares with the installed version
3. Downloads if update is available (with SHA256 verification)
4. Installs via `rpm -U`
5. Restarts the service

#### Manual — direct command

```bash
curl -sk https://<server>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -U --force /tmp/raid-agent.rpm && \
  systemctl restart raid-agent
```

> Config file is preserved during updates (`%config(noreplace)`).

### File Structure After Installation

```
/opt/raid-agent/                    # Application
├── venv/                           # Python virtualenv
├── raid_agent/                     # Source code
│   ├── __init__.py                 # Version
│   ├── main.py                     # Entry point, daemon loop
│   ├── config.py                   # Config loader
│   ├── collector.py                # RAID data collection (storcli64)
│   ├── system_info.py              # OS/hardware info
│   ├── reporter.py                 # HTTP communication with server
│   ├── installer.py                # storcli64 auto-install
│   ├── updater.py                  # Agent auto-update
│   └── selinux/                    # SELinux policies
├── setup.py
└── update-agent.sh                 # Update script

/etc/raid-agent/
└── config.yml                      # Configuration (0600, root:root)

/var/log/raid-agent/
└── agent.log                       # Logs (rotated daily, 14 days)

/usr/lib/systemd/system/
└── raid-agent.service              # systemd service

/etc/logrotate.d/
└── raid-agent                      # Log rotation config

/usr/local/bin/
└── raid-agent → /opt/raid-agent/venv/bin/raid-agent  # Symlink
```

### Useful Commands

| Command | Description |
|---------|-------------|
| `systemctl status raid-agent` | Service status |
| `systemctl restart raid-agent` | Restart service |
| `systemctl stop raid-agent` | Stop service |
| `journalctl -u raid-agent -f` | Live logs (journald) |
| `tail -f /var/log/raid-agent/agent.log` | Live logs (file) |
| `raid-agent --register` | Register with server |
| `cat /etc/raid-agent/config.yml` | View config |
| `rpm -qi raid-agent` | Package info |
| `rpm -e raid-agent` | Uninstall agent |

### Systemd Service

```ini
[Unit]
Description=RAID Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/raid-agent/venv/bin/python -m raid_agent.main
WorkingDirectory=/opt/raid-agent
Restart=on-failure
RestartSec=30
User=root
Group=root
Environment=PYTHONPATH=/opt/raid-agent

[Install]
WantedBy=multi-user.target
```

Key points:
- Runs as root (required for storcli64)
- Auto-restarts on failure with 30-second delay
- Logs to systemd journal
- Waits for network before starting

### Troubleshooting

**Agent not starting:**
```bash
systemctl status raid-agent
journalctl -u raid-agent --no-pager -n 50
```

**Registration fails:**
```bash
# Check network
curl -sk https://<server>/api/v1/health

# Check config
cat /etc/raid-agent/config.yml

# Run registration with debug
raid-agent --register --debug
```

**No RAID data collected:**
```bash
# Check storcli64 is installed and working
storcli64 show

# Check if agent can find it
grep storcli /var/log/raid-agent/agent.log
```

**Agent not appearing on dashboard:**
- Verify `api_key` is set in config: `grep api_key /etc/raid-agent/config.yml`
- Check agent logs for errors: `journalctl -u raid-agent -f`
- Check network connectivity: `curl -sk https://<server>/api/v1/health`

### Uninstall

```bash
systemctl stop raid-agent
systemctl disable raid-agent
rpm -e raid-agent
```

This removes the application but preserves:
- Config: `/etc/raid-agent/config.yml`
- Logs: `/var/log/raid-agent/`

To fully clean up:
```bash
rm -rf /etc/raid-agent /var/log/raid-agent /opt/raid-agent
```

---

<a id="russian"></a>

## Русский

### Требования

| Компонент | Требование |
|-----------|------------|
| ОС | RHEL / CentOS / Rocky / Alma Linux 7, 8, 9 (x86_64) |
| Python | 3.9+ |
| Доступ | root (необходим для storcli64) |
| Сеть | HTTPS-доступ к серверу мониторинга (порт 443) |
| RAID | Контроллер Broadcom/LSI MegaRAID или Dell PERC |

### Способы установки

#### Способ 1: Скачать с сервера (рекомендуется)

```bash
curl -sk https://<сервер>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm
rpm -ivh /tmp/raid-agent.rpm
sed -i 's|https://raid-monitor.example.com|https://<сервер>|' /etc/raid-agent/config.yml
raid-agent --register
systemctl enable --now raid-agent
```

**Одной командой:**

```bash
curl -sk https://<сервер>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -ivh /tmp/raid-agent.rpm && \
  sed -i 's|https://raid-monitor.example.com|https://<сервер>|' /etc/raid-agent/config.yml && \
  raid-agent --register && \
  systemctl enable --now raid-agent
```

#### Способ 2: Копирование RPM вручную

```bash
# С административной машины
scp raid-agent-1.0.4-1.el8.noarch.rpm root@target-server:/tmp/

# На целевом сервере
rpm -ivh /tmp/raid-agent-1.0.4-1.el8.noarch.rpm
```

### Пошаговая установка

#### Шаг 1. Установить RPM

```bash
rpm -ivh raid-agent-1.0.4-1.el8.noarch.rpm
```

RPM-установщик автоматически:
- Создаёт Python virtualenv в `/opt/raid-agent/venv`
- Устанавливает зависимости (`requests`, `pyyaml`)
- Создаёт симлинк `/usr/local/bin/raid-agent`
- Устанавливает systemd-сервис `raid-agent.service`
- Создаёт конфиг в `/etc/raid-agent/config.yml`
- Настраивает ротацию логов (`/etc/logrotate.d/raid-agent`)
- Собирает и устанавливает SELinux-политику (если доступно)

#### Шаг 2. Настроить

Отредактируйте файл конфигурации:

```bash
vi /etc/raid-agent/config.yml
```

**Обязательно:** укажите `server_url` вашего сервера мониторинга:

```yaml
server_url: "https://raid-monitor.example.com"
```

Если сервер использует самоподписанный сертификат:

```yaml
ssl_verify: false
```

Полный справочник: [Справочник конфигурации (Configuration Reference)](Configuration-Reference.md)

#### Шаг 3. Зарегистрировать

```bash
raid-agent --register
```

Что происходит:
1. Агент собирает информацию о системе (hostname, IP, ОС)
2. Отправляет `POST /api/v1/agent/register` на сервер
3. Сервер создаёт запись и возвращает API-ключ
4. Агент сохраняет API-ключ в `/etc/raid-agent/config.yml`

Ожидаемый вывод:
```
Registration successful!
Server ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
API key saved to /etc/raid-agent/config.yml
```

#### Шаг 4. Запустить сервис

```bash
systemctl enable --now raid-agent
```

Проверка:
```bash
systemctl status raid-agent
```

Агент будет:
1. Находить или автоматически устанавливать `storcli64`
2. Собирать данные RAID
3. Отправлять первый отчёт на сервер
4. Повторять каждые 10 минут
5. Опрашивать команды каждые 30 секунд

### StorCLI (storcli64)

Агенту нужен `storcli64` для сбора данных RAID. Автоматический поиск в:

| Путь | Описание |
|------|----------|
| `/opt/MegaRAID/storcli/storcli64` | Стандартное расположение MegaRAID |
| `/opt/MegaRAID/storcli64/storcli64` | Альтернативное расположение |
| `/usr/local/bin/storcli64` | Локальный bin |
| `/usr/bin/storcli64` | Системный bin |
| `/usr/sbin/storcli64` | Системный sbin |
| `/opt/MegaRAID/perccli/perccli64` | Dell PERC (запасной) |
| `/opt/dell/perccli/perccli64` | Dell альтернативный |

**Автоустановка с сервера:** Если storcli64 не найден и администратор загрузил RPM в Настройки → Агенты → Пакет StorCLI, агент скачает и установит его автоматически.

**Ручная установка:**

```bash
rpm -ivh storcli-007.2705.0000.0000-1.noarch.rpm
```

### Обновление агента

#### Автоматическое

Если администратор загрузил новый RPM агента в Настройки → Агенты → Пакет агента, агент обнаружит обновление и установит его автоматически.

#### Вручную — через скрипт обновления

```bash
bash /opt/raid-agent/update-agent.sh https://<сервер>
```

Скрипт:
1. Проверяет на сервере последнюю версию
2. Сравнивает с установленной
3. Скачивает при наличии обновления (с проверкой SHA256)
4. Устанавливает через `rpm -U`
5. Перезапускает сервис

#### Вручную — прямой командой

```bash
curl -sk https://<сервер>/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && \
  rpm -U --force /tmp/raid-agent.rpm && \
  systemctl restart raid-agent
```

> Конфигурация сохраняется при обновлении (`%config(noreplace)`).

### Структура файлов после установки

```
/opt/raid-agent/                    # Приложение
├── venv/                           # Python virtualenv
├── raid_agent/                     # Исходный код
│   ├── __init__.py                 # Версия
│   ├── main.py                     # Точка входа, цикл демона
│   ├── config.py                   # Загрузка конфигурации
│   ├── collector.py                # Сбор данных RAID (storcli64)
│   ├── system_info.py              # Информация об ОС/железе
│   ├── reporter.py                 # HTTP-связь с сервером
│   ├── installer.py                # Автоустановка storcli64
│   ├── updater.py                  # Автообновление агента
│   └── selinux/                    # SELinux-политики
├── setup.py
└── update-agent.sh                 # Скрипт обновления

/etc/raid-agent/
└── config.yml                      # Конфигурация (0600, root:root)

/var/log/raid-agent/
└── agent.log                       # Логи (ротация ежедневно, 14 дней)

/usr/lib/systemd/system/
└── raid-agent.service              # systemd-сервис

/etc/logrotate.d/
└── raid-agent                      # Конфигурация ротации логов

/usr/local/bin/
└── raid-agent → /opt/raid-agent/venv/bin/raid-agent  # Симлинк
```

### Полезные команды

| Команда | Описание |
|---------|----------|
| `systemctl status raid-agent` | Статус сервиса |
| `systemctl restart raid-agent` | Перезапуск сервиса |
| `systemctl stop raid-agent` | Остановка сервиса |
| `journalctl -u raid-agent -f` | Логи в реальном времени (journald) |
| `tail -f /var/log/raid-agent/agent.log` | Логи в реальном времени (файл) |
| `raid-agent --register` | Регистрация на сервере |
| `cat /etc/raid-agent/config.yml` | Просмотр конфига |
| `rpm -qi raid-agent` | Информация о пакете |
| `rpm -e raid-agent` | Удаление агента |

### Systemd-сервис

```ini
[Unit]
Description=RAID Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/raid-agent/venv/bin/python -m raid_agent.main
WorkingDirectory=/opt/raid-agent
Restart=on-failure
RestartSec=30
User=root
Group=root
Environment=PYTHONPATH=/opt/raid-agent

[Install]
WantedBy=multi-user.target
```

Ключевые моменты:
- Работает от root (требуется для storcli64)
- Автоматический перезапуск при сбое (задержка 30 секунд)
- Логи в systemd journal
- Ожидает сеть перед запуском

### Диагностика проблем

**Агент не запускается:**
```bash
systemctl status raid-agent
journalctl -u raid-agent --no-pager -n 50
```

**Ошибка регистрации:**
```bash
# Проверить сеть
curl -sk https://<сервер>/api/v1/health

# Проверить конфиг
cat /etc/raid-agent/config.yml

# Запустить регистрацию с отладкой
raid-agent --register --debug
```

**Данные RAID не собираются:**
```bash
# Проверить что storcli64 установлен и работает
storcli64 show

# Проверить может ли агент его найти
grep storcli /var/log/raid-agent/agent.log
```

**Агент не появляется на Dashboard:**
- Проверьте что `api_key` задан: `grep api_key /etc/raid-agent/config.yml`
- Проверьте логи агента: `journalctl -u raid-agent -f`
- Проверьте связь: `curl -sk https://<сервер>/api/v1/health`

### Удаление

```bash
systemctl stop raid-agent
systemctl disable raid-agent
rpm -e raid-agent
```

Это удалит приложение, но сохранит:
- Конфиг: `/etc/raid-agent/config.yml`
- Логи: `/var/log/raid-agent/`

Для полной очистки:
```bash
rm -rf /etc/raid-agent /var/log/raid-agent /opt/raid-agent
```
