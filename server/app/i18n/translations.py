"""Simple i18n translation system for RAID Monitor."""

TRANSLATIONS = {
    "en": {
        # Navigation
        "nav.dashboard": "Dashboard",
        "nav.alerts": "Alerts",
        "nav.settings": "Settings",
        "nav.logout": "Logout",
        "nav.login": "Login",

        # Dashboard
        "dashboard.title": "Dashboard",
        "dashboard.servers": "Servers",
        "dashboard.controllers": "Controllers",
        "dashboard.virtual_drives": "Virtual Drives",
        "dashboard.physical_drives": "Physical Drives",
        "dashboard.online": "online",
        "dashboard.offline": "offline",
        "dashboard.ok": "OK",
        "dashboard.problem": "problem",
        "dashboard.no_servers": "No servers registered yet",
        "dashboard.search": "Search hostname...",
        "dashboard.filter_status": "All statuses",
        "dashboard.sort_by": "Sort by",
        "dashboard.last_seen": "Last seen",
        "dashboard.ago": "ago",

        # Server detail
        "server.overview": "Overview",
        "server.controllers": "Controllers",
        "server.virtual_drives": "Virtual Drives",
        "server.physical_drives": "Physical Drives",
        "server.events": "Events",
        "server.agent": "Agent",
        "server.hostname": "Hostname",
        "server.ip_address": "IP Address",
        "server.os": "Operating System",
        "server.kernel": "Kernel",
        "server.cpu": "CPU",
        "server.ram": "RAM",
        "server.uptime": "Uptime",
        "server.agent_version": "Agent Version",
        "server.storcli_version": "StorCLI Version",
        "server.last_update": "Last OS Update",
        "server.registered": "Registered",
        "server.delete": "Delete Server",
        "server.delete_confirm": "Are you sure you want to delete this server?",

        # Controller
        "ctrl.model": "Model",
        "ctrl.serial": "Serial Number",
        "ctrl.firmware": "Firmware",
        "ctrl.bios": "BIOS",
        "ctrl.driver": "Driver",
        "ctrl.status": "Status",
        "ctrl.memory": "Memory",
        "ctrl.temperature": "Temperature",
        "ctrl.rebuild_rate": "Rebuild Rate",
        "ctrl.patrol_read": "Patrol Read",
        "ctrl.cc_status": "Consistency Check",
        "ctrl.alarm": "Alarm",
        "ctrl.bbu": "Battery / CacheVault",
        "ctrl.bbu_state": "State",
        "ctrl.bbu_temp": "Temperature",
        "ctrl.bbu_replacement": "Replacement Needed",

        # Virtual Drive
        "vd.id": "VD#",
        "vd.name": "Name",
        "vd.raid": "RAID",
        "vd.state": "State",
        "vd.size": "Size",
        "vd.cache": "Cache",
        "vd.io": "IO Policy",
        "vd.read": "Read Policy",
        "vd.drives": "Drives",
        "vd.consistent": "Consistent",

        # Physical Drive
        "pd.eid_slot": "EID:Slot",
        "pd.state": "State",
        "pd.dg": "DG",
        "pd.size": "Size",
        "pd.model": "Model",
        "pd.type": "Type",
        "pd.interface": "Interface",
        "pd.temp": "Temp",
        "pd.media_err": "Media Err",
        "pd.other_err": "Other Err",
        "pd.pred_fail": "Pred. Fail",
        "pd.smart": "SMART",
        "pd.serial": "Serial",
        "pd.firmware": "Firmware",

        # Events
        "event.time": "Time",
        "event.severity": "Severity",
        "event.class": "Class",
        "event.description": "Description",
        "event.filter_severity": "All severities",

        # Alerts
        "alerts.title": "Alerts",
        "alerts.active": "Active Alerts",
        "alerts.history": "Alert History",
        "alerts.rules": "Alert Rules",
        "alerts.no_active": "No active alerts",
        "alerts.resolve": "Resolve",
        "alerts.resolved": "Resolved",
        "alerts.rule_name": "Rule",
        "alerts.category": "Category",
        "alerts.severity": "Severity",
        "alerts.enabled": "Enabled",
        "alerts.cooldown": "Cooldown (min)",
        "alerts.telegram": "Telegram",
        "alerts.builtin": "Built-in",
        "alerts.server": "Server",
        "alerts.message": "Message",
        "alerts.time": "Time",
        "alerts.status": "Status",

        # Settings
        "settings.title": "Settings",
        "settings.general": "General",
        "settings.ldap": "LDAP",
        "settings.telegram": "Telegram",
        "settings.ssl": "SSL Certificate",
        "settings.agents": "Agent Packages",
        "settings.debug": "Debug",
        "settings.save": "Save",
        "settings.saved": "Settings saved",
        "settings.test": "Test Connection",
        "settings.test_message": "Send Test Message",
        "settings.upload": "Upload",
        "settings.enabled": "Enabled",
        "settings.disabled": "Disabled",

        # LDAP
        "ldap.server_url": "Server URL",
        "ldap.bind_dn": "Bind DN",
        "ldap.bind_password": "Bind Password",
        "ldap.search_base": "Search Base",
        "ldap.user_filter": "User Filter",
        "ldap.group_filter": "Group Filter",
        "ldap.admin_group": "Admin Group",

        # Telegram
        "tg.bot_token": "Bot Token",
        "tg.chat_id": "Chat ID",

        # SSL
        "ssl.current_cert": "Current Certificate",
        "ssl.subject": "Subject",
        "ssl.issuer": "Issuer",
        "ssl.valid_from": "Valid From",
        "ssl.valid_to": "Valid To",
        "ssl.days_left": "Days Until Expiry",
        "ssl.upload_cert": "Upload Certificate",
        "ssl.cert_file": "Certificate File (.crt/.pem)",
        "ssl.key_file": "Key File (.key/.pem)",

        # Agent settings
        "agent.current_version": "Current Agent Version",
        "agent.upload_rpm": "Upload Agent RPM",
        "agent.upload_storcli": "Upload StorCLI RPM",
        "agent.packages": "Agent Packages",
        "agent.set_current": "Set as Current",
        "agent.debug_mode": "Debug Mode",
        "agent.collect_logs": "Collect Logs",
        "agent.collect_all_logs": "Collect All Agent Logs",
        "agent.upload_logs": "Upload Logs to File Server",

        # General
        "general.language": "Default Language",
        "general.retention": "Data Retention (days)",
        "general.auto_approve": "Auto-approve new agents",

        # Status
        "status.online": "Online",
        "status.offline": "Offline",
        "status.warning": "Warning",
        "status.critical": "Critical",
        "status.unknown": "Unknown",

        # Auth
        "auth.username": "Username",
        "auth.password": "Password",
        "auth.login": "Sign In",
        "auth.login_error": "Invalid username or password",
        "auth.login_title": "RAID Monitor",
        "auth.login_subtitle": "Sign in to your account",

        # Time
        "time.just_now": "just now",
        "time.minutes": "min",
        "time.hours": "h",
        "time.days": "d",
    },

    "ru": {
        # Navigation
        "nav.dashboard": "Панель управления",
        "nav.alerts": "Алерты",
        "nav.settings": "Настройки",
        "nav.logout": "Выход",
        "nav.login": "Вход",

        # Dashboard
        "dashboard.title": "Панель управления",
        "dashboard.servers": "Серверы",
        "dashboard.controllers": "Контроллеры",
        "dashboard.virtual_drives": "Виртуальные массивы",
        "dashboard.physical_drives": "Физические диски",
        "dashboard.online": "в сети",
        "dashboard.offline": "не в сети",
        "dashboard.ok": "OK",
        "dashboard.problem": "проблема",
        "dashboard.no_servers": "Нет зарегистрированных серверов",
        "dashboard.search": "Поиск по hostname...",
        "dashboard.filter_status": "Все статусы",
        "dashboard.sort_by": "Сортировка",
        "dashboard.last_seen": "Последнее обращение",
        "dashboard.ago": "назад",

        # Server detail
        "server.overview": "Обзор",
        "server.controllers": "Контроллеры",
        "server.virtual_drives": "Виртуальные массивы",
        "server.physical_drives": "Физические диски",
        "server.events": "События",
        "server.agent": "Агент",
        "server.hostname": "Имя хоста",
        "server.ip_address": "IP адрес",
        "server.os": "Операционная система",
        "server.kernel": "Ядро",
        "server.cpu": "Процессор",
        "server.ram": "Оперативная память",
        "server.uptime": "Время работы",
        "server.agent_version": "Версия агента",
        "server.storcli_version": "Версия StorCLI",
        "server.last_update": "Последнее обновление ОС",
        "server.registered": "Зарегистрирован",
        "server.delete": "Удалить сервер",
        "server.delete_confirm": "Вы уверены, что хотите удалить этот сервер?",

        # Controller
        "ctrl.model": "Модель",
        "ctrl.serial": "Серийный номер",
        "ctrl.firmware": "Прошивка",
        "ctrl.bios": "BIOS",
        "ctrl.driver": "Драйвер",
        "ctrl.status": "Статус",
        "ctrl.memory": "Память",
        "ctrl.temperature": "Температура",
        "ctrl.rebuild_rate": "Скорость Rebuild",
        "ctrl.patrol_read": "Patrol Read",
        "ctrl.cc_status": "Проверка целостности",
        "ctrl.alarm": "Сигнализация",
        "ctrl.bbu": "Батарея / CacheVault",
        "ctrl.bbu_state": "Состояние",
        "ctrl.bbu_temp": "Температура",
        "ctrl.bbu_replacement": "Требуется замена",

        # Virtual Drive
        "vd.id": "VD#",
        "vd.name": "Имя",
        "vd.raid": "RAID",
        "vd.state": "Состояние",
        "vd.size": "Размер",
        "vd.cache": "Кэш",
        "vd.io": "Политика IO",
        "vd.read": "Политика чтения",
        "vd.drives": "Диски",
        "vd.consistent": "Консистентный",

        # Physical Drive
        "pd.eid_slot": "EID:Слот",
        "pd.state": "Состояние",
        "pd.dg": "DG",
        "pd.size": "Размер",
        "pd.model": "Модель",
        "pd.type": "Тип",
        "pd.interface": "Интерфейс",
        "pd.temp": "Темп.",
        "pd.media_err": "Media Err",
        "pd.other_err": "Other Err",
        "pd.pred_fail": "Pred. Fail",
        "pd.smart": "SMART",
        "pd.serial": "Серийный номер",
        "pd.firmware": "Прошивка",

        # Events
        "event.time": "Время",
        "event.severity": "Серьёзность",
        "event.class": "Класс",
        "event.description": "Описание",
        "event.filter_severity": "Все уровни",

        # Alerts
        "alerts.title": "Алерты",
        "alerts.active": "Активные алерты",
        "alerts.history": "История алертов",
        "alerts.rules": "Правила алертов",
        "alerts.no_active": "Нет активных алертов",
        "alerts.resolve": "Разрешить",
        "alerts.resolved": "Разрешён",
        "alerts.rule_name": "Правило",
        "alerts.category": "Категория",
        "alerts.severity": "Серьёзность",
        "alerts.enabled": "Включено",
        "alerts.cooldown": "Интервал (мин)",
        "alerts.telegram": "Telegram",
        "alerts.builtin": "Встроенное",
        "alerts.server": "Сервер",
        "alerts.message": "Сообщение",
        "alerts.time": "Время",
        "alerts.status": "Статус",

        # Settings
        "settings.title": "Настройки",
        "settings.general": "Общие",
        "settings.ldap": "LDAP",
        "settings.telegram": "Telegram",
        "settings.ssl": "SSL сертификат",
        "settings.agents": "Пакеты агента",
        "settings.debug": "Отладка",
        "settings.save": "Сохранить",
        "settings.saved": "Настройки сохранены",
        "settings.test": "Проверить подключение",
        "settings.test_message": "Отправить тестовое сообщение",
        "settings.upload": "Загрузить",
        "settings.enabled": "Включено",
        "settings.disabled": "Отключено",

        # LDAP
        "ldap.server_url": "URL сервера",
        "ldap.bind_dn": "Bind DN",
        "ldap.bind_password": "Пароль привязки",
        "ldap.search_base": "База поиска",
        "ldap.user_filter": "Фильтр пользователей",
        "ldap.group_filter": "Фильтр групп",
        "ldap.admin_group": "Группа администраторов",

        # Telegram
        "tg.bot_token": "Токен бота",
        "tg.chat_id": "ID чата",

        # SSL
        "ssl.current_cert": "Текущий сертификат",
        "ssl.subject": "Субъект",
        "ssl.issuer": "Издатель",
        "ssl.valid_from": "Действителен с",
        "ssl.valid_to": "Действителен до",
        "ssl.days_left": "Дней до истечения",
        "ssl.upload_cert": "Загрузить сертификат",
        "ssl.cert_file": "Файл сертификата (.crt/.pem)",
        "ssl.key_file": "Файл ключа (.key/.pem)",

        # Agent settings
        "agent.current_version": "Текущая версия агента",
        "agent.upload_rpm": "Загрузить RPM агента",
        "agent.upload_storcli": "Загрузить RPM StorCLI",
        "agent.packages": "Пакеты агента",
        "agent.set_current": "Установить текущим",
        "agent.debug_mode": "Режим отладки",
        "agent.collect_logs": "Собрать логи",
        "agent.collect_all_logs": "Собрать логи всех агентов",
        "agent.upload_logs": "Загрузить логи на файл-сервер",

        # General
        "general.language": "Язык по умолчанию",
        "general.retention": "Хранение данных (дней)",
        "general.auto_approve": "Авто-одобрение агентов",

        # Status
        "status.online": "В сети",
        "status.offline": "Не в сети",
        "status.warning": "Предупреждение",
        "status.critical": "Критический",
        "status.unknown": "Неизвестно",

        # Auth
        "auth.username": "Имя пользователя",
        "auth.password": "Пароль",
        "auth.login": "Войти",
        "auth.login_error": "Неверное имя пользователя или пароль",
        "auth.login_title": "RAID Monitor",
        "auth.login_subtitle": "Войдите в систему",

        # Time
        "time.just_now": "только что",
        "time.minutes": "мин",
        "time.hours": "ч",
        "time.days": "д",
    },
}


def get_translator(lang: str = "en"):
    """Return translation function for given language."""
    translations = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    fallback = TRANSLATIONS["en"]

    def _(key: str, **kwargs) -> str:
        text = translations.get(key, fallback.get(key, key))
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, IndexError):
                pass
        return text

    return _
