"""
RAID Monitor - Web (HTML) Routes
All Jinja2 template rendering routes for the frontend.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

import logging

from fastapi import APIRouter, Request, Depends, Query, Cookie, HTTPException, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router & Templates setup
# ---------------------------------------------------------------------------

router = APIRouter(tags=["web"])

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)

# ---------------------------------------------------------------------------
# Simple i18n helper
# ---------------------------------------------------------------------------

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "ru": {
        "Dashboard": "Панель управления",
        "Alerts": "Оповещения",
        "Settings": "Настройки",
        "Logout": "Выход",
        "Login": "Вход",
        "Sign in to your account": "Войдите в свой аккаунт",
        "Username": "Имя пользователя",
        "Password": "Пароль",
        "Enter username": "Введите имя пользователя",
        "Enter password": "Введите пароль",
        "Sign In": "Войти",
        "Servers": "Серверы",
        "Controllers": "Контроллеры",
        "Virtual Drives": "Виртуальные диски",
        "Physical Drives": "Физические диски",
        "Search": "Поиск",
        "Search hostname or IP...": "Поиск по имени или IP...",
        "Status": "Статус",
        "Sort": "Сортировка",
        "All": "Все",
        "Online": "В сети",
        "Offline": "Не в сети",
        "Warning": "Предупреждение",
        "Critical": "Критический",
        "Hostname": "Имя хоста",
        "Last Seen": "Последнее подключение",
        "Refresh": "Обновить",
        "No servers found": "Серверы не найдены",
        "Servers will appear here once agents start reporting.": "Серверы появятся здесь, когда агенты начнут отправлять данные.",
        "Agent": "Агент",
        "Overview": "Обзор",
        "Events": "События",
        "Kernel": "Ядро",
        "Uptime": "Время работы",
        "Last seen": "Последнее подключение",
        "Active Alerts": "Активные оповещения",
        "Recent Events": "Последние события",
        "Time": "Время",
        "Severity": "Серьёзность",
        "Description": "Описание",
        "Loading...": "Загрузка...",
        "Loading controllers...": "Загрузка контроллеров...",
        "Loading virtual drives...": "Загрузка виртуальных дисков...",
        "Loading physical drives...": "Загрузка физических дисков...",
        "Loading events...": "Загрузка событий...",
        "Loading agent info...": "Загрузка информации об агенте...",
        "Serial": "Серийный номер",
        "Firmware": "Прошивка",
        "Rebuild Rate": "Скорость ребилда",
        "Patrol Read": "Патрульное чтение",
        "CC Status": "Статус CC",
        "Alarm": "Сигнализация",
        "Temperature": "Температура",
        "Memory": "Память",
        "Correctable Errors": "Исправимые ошибки",
        "Uncorrectable Errors": "Неисправимые ошибки",
        "Name": "Имя",
        "State": "Состояние",
        "Size": "Размер",
        "Cache": "Кэш",
        "Read": "Чтение",
        "Drives": "Диски",
        "Model": "Модель",
        "Type": "Тип",
        "Interface": "Интерфейс",
        "Temp": "Темп",
        "Media Errors": "Ошибки носителя",
        "Other Errors": "Другие ошибки",
        "Predictive Failure": "Прогноз отказа",
        "SMART Alert": "SMART предупреждение",
        "SMART Data": "Данные SMART",
        "Click for SMART details": "Нажмите для деталей SMART",
        "Close": "Закрыть",
        "Class": "Класс",
        "All Severities": "Все уровни",
        "Info": "Информация",
        "No controllers found for this server.": "Контроллеры для этого сервера не найдены.",
        "No virtual drives found for this server.": "Виртуальные диски для этого сервера не найдены.",
        "No physical drives found for this server.": "Физические диски для этого сервера не найдены.",
        "No events found for this server.": "События для этого сервера не найдены.",
        "Agent Version": "Версия агента",
        "StorCLI Version": "Версия StorCLI",
        "Registered": "Зарегистрирован",
        "Debug Logging": "Отладочное логирование",
        "Enable debug mode": "Включить режим отладки",
        "Collect Logs": "Собрать логи",
        "Active Alerts": "Активные оповещения",
        "Alert History": "История оповещений",
        "Alert Rules": "Правила оповещений",
        "No active alerts": "Нет активных оповещений",
        "All systems are operating normally.": "Все системы работают нормально.",
        "Resolve": "Решить",
        "Resolve this alert?": "Решить это оповещение?",
        "Server": "Сервер",
        "Title": "Заголовок",
        "Resolved at": "Решено в",
        "Resolved": "Решено",
        "Active": "Активно",
        "All Servers": "Все серверы",
        "From": "С",
        "To": "По",
        "Category": "Категория",
        "Enabled": "Включено",
        "Cooldown": "Интервал",
        "Telegram": "Telegram",
        "Built-in rule": "Встроенное правило",
        "min": "мин",
        "General": "Общие",
        "General Settings": "Общие настройки",
        "Default Language": "Язык по умолчанию",
        "Default language for the web interface.": "Язык по умолчанию для веб-интерфейса.",
        "Data Retention (days)": "Хранение данных (дни)",
        "Number of days to keep historical data (events, alerts, metrics).": "Количество дней хранения исторических данных (события, оповещения, метрики).",
        "Auto-approve new agents": "Автоматически одобрять новые агенты",
        "Automatically approve new agent registrations without manual confirmation.": "Автоматически одобрять регистрации новых агентов без ручного подтверждения.",
        "Save": "Сохранить",
        "LDAP Settings": "Настройки LDAP",
        "Enable LDAP": "Включить LDAP",
        "Server URL": "URL сервера",
        "Bind DN": "Bind DN",
        "Bind Password": "Пароль привязки",
        "Enter bind password": "Введите пароль привязки",
        "Search Base": "База поиска",
        "User Filter": "Фильтр пользователей",
        "Group Filter": "Фильтр групп",
        "Admin Group": "Группа администраторов",
        "Members of this group will have admin privileges.": "Участники этой группы получат права администратора.",
        "Test Connection": "Тест подключения",
        "Telegram Notifications": "Уведомления Telegram",
        "Enable": "Включить",
        "Bot Token": "Токен бота",
        "Chat ID": "ID чата",
        "Send Test Message": "Отправить тестовое сообщение",
        "Current Certificate": "Текущий сертификат",
        "Subject": "Субъект",
        "Issuer": "Издатель",
        "Valid From": "Действителен с",
        "Valid To": "Действителен до",
        "days left": "дней осталось",
        "days": "дней",
        "Certificate expires in": "Сертификат истекает через",
        "Please renew it soon.": "Пожалуйста, обновите его в ближайшее время.",
        "Upload Certificate": "Загрузить сертификат",
        "Certificate File": "Файл сертификата",
        "Private Key File": "Файл приватного ключа",
        "Upload": "Загрузить",
        "Agent Package": "Пакет агента",
        "Current Version": "Текущая версия",
        "Upload Agent RPM": "Загрузить RPM агента",
        "Uploaded Packages": "Загруженные пакеты",
        "Version": "Версия",
        "Filename": "Имя файла",
        "Uploaded": "Загружен",
        "Actions": "Действия",
        "Current": "Текущий",
        "Set Current": "Установить текущим",
        "Set this version as current?": "Установить эту версию текущей?",
        "No packages uploaded yet.": "Пакеты ещё не загружены.",
        "StorCLI Package": "Пакет StorCLI",
        "Upload storcli64 RPM": "Загрузить RPM storcli64",
        "Upload the storcli64 RPM package for agent distribution.": "Загрузите RPM пакет storcli64 для распространения через агенты.",
        "Agents": "Агенты",
        "Debug": "Отладка",
        "Web Application Debug": "Отладка веб-приложения",
        "Enable debug logging for web application": "Включить отладочное логирование для веб-приложения",
        "When enabled, the web application will log detailed debug information. This may impact performance.": "При включении веб-приложение будет записывать подробную отладочную информацию. Это может влиять на производительность.",
        "Agent Debug Settings": "Настройки отладки агентов",
        "Collect All Logs": "Собрать все логи",
        "Collect logs from all agents?": "Собрать логи со всех агентов?",
        "No agents registered.": "Нет зарегистрированных агентов.",
        "Log Upload": "Загрузка логов",
        "Upload collected logs to the file server for analysis.": "Загрузить собранные логи на файловый сервер для анализа.",
        "Upload Logs to File Server": "Загрузить логи на файловый сервер",
        "Page navigation": "Навигация по страницам",
        "Previous": "Предыдущая",
        "Next": "Следующая",
        "Page": "Страница",
        "of": "из",
        "items": "записей",
        "problem": "проблема",
        "Settings saved successfully.": "Настройки успешно сохранены.",
    },
    "en": {},
}


def _make_gettext(lang: str):
    """Return a simple translation function for the given language."""
    trans = _TRANSLATIONS.get(lang, {})

    def _gettext(text: str) -> str:
        return trans.get(text, text)

    return _gettext


# ---------------------------------------------------------------------------
# Auth dependency stub
# ---------------------------------------------------------------------------

async def _get_current_user(request: Request) -> Optional[dict]:
    """
    Check access_token JWT cookie and return user dict or None.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        from jose import jwt
        from app.config import settings
        from app.dependencies import JWT_ALGORITHM
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        return {
            "username": username,
            "id": payload.get("uid"),
            "is_admin": payload.get("admin", False),
        }
    except Exception:
        return None


async def _require_auth(request: Request) -> dict:
    """Dependency that redirects to login if not authenticated."""
    user = await _get_current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        raise HTTPException(status_code=303, detail="Not authenticated",
                            headers={"Location": "/login"})
    return user


# ---------------------------------------------------------------------------
# Common template context
# ---------------------------------------------------------------------------

def _get_lang(request: Request) -> str:
    """Determine language from query param, cookie, or default."""
    lang = request.query_params.get("lang")
    if lang in ("ru", "en"):
        return lang
    lang = request.cookies.get("lang")
    if lang in ("ru", "en"):
        return lang
    return "en"


def _base_context(request: Request, active_page: str = "", **extra) -> dict:
    """Build base template context with common variables."""
    lang = _get_lang(request)
    ctx = {
        "request": request,
        "lang": lang,
        "_": _make_gettext(lang),
        "active_page": active_page,
        "csrf_token": request.cookies.get("csrf_token", ""),
        "version": "1.0.0",
        "current_year": datetime.now().year,
        "active_alerts_count": 0,
        "current_user": None,
    }
    ctx.update(extra)
    return ctx


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """Redirect root to dashboard."""
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(
    request: Request,
    error: Optional[str] = None,
    lang: Optional[str] = None,
):
    """Render the login page."""
    ctx = _base_context(request, active_page="login", error=error)
    response = templates.TemplateResponse("login.html", ctx)
    if lang and lang in ("ru", "en"):
        response.set_cookie("lang", lang, max_age=31536000)
    return response


@router.post("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Handle login form submission."""
    import bcrypt as _bcrypt
    from jose import jwt
    from datetime import timedelta, timezone
    from app.config import settings
    from app.database import async_session
    from app.models.user import User
    from app.models.setting import Setting
    from app.dependencies import JWT_ALGORITHM
    from sqlalchemy import select

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        authenticated = False

        # Local auth
        if user and user.auth_source == "local" and user.password_hash:
            try:
                if _bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
                    if not user.is_active:
                        ctx = _base_context(request, active_page="login", error=_("User account is disabled"))
                        return templates.TemplateResponse("login.html", ctx)
                    authenticated = True
            except Exception:
                pass

        # LDAP fallback
        if not authenticated:
            try:
                from app.services.ldap_auth import ldap_authenticate
                ldap_result = await ldap_authenticate(db, username, password)
                if ldap_result:
                    if user is None:
                        user = User(
                            username=username,
                            display_name=ldap_result.get("display_name", username),
                            auth_source="ldap",
                            is_active=True,
                            is_admin=ldap_result.get("is_admin", False),
                            language=lang,
                        )
                        db.add(user)
                        await db.commit()
                        await db.refresh(user)
                    authenticated = True
            except Exception:
                pass

        if not authenticated:
            ctx = _base_context(request, active_page="login", error=_("Invalid credentials"))
            return templates.TemplateResponse("login.html", ctx)

        # Create JWT token
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
        token_data = {
            "sub": user.username,
            "uid": str(user.id),
            "admin": user.is_admin,
            "exp": expire,
        }
        token = jwt.encode(token_data, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)

        # Redirect to dashboard with token in cookie
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            "access_token", token,
            max_age=86400, httponly=True, samesite="lax", secure=True,
        )
        response.set_cookie("lang", user.language or lang, max_age=31536000)
        return response


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear auth cookie and redirect to login."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(
    request: Request,
    search: Optional[str] = "",
    status: Optional[str] = "",
    sort: Optional[str] = "hostname",
    page: int = Query(1, ge=1),
    partial: Optional[int] = None,
    lang: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render the main dashboard with server list."""
    # In production, fetch from database. Stub data for template rendering.
    servers = []
    stats = {
        "servers_online": 0,
        "servers_total": 0,
        "controllers_total": 0,
        "vd_ok": 0,
        "vd_total": 0,
        "vd_problem": 0,
        "pd_ok": 0,
        "pd_total": 0,
        "pd_problem": 0,
    }

    pagination = {
        "current_page": page,
        "total_pages": 1,
        "total_items": 0,
        "base_url": "/dashboard",
        "params": {},
        "htmx": True,
        "htmx_target": "#server-list",
    }
    if search:
        pagination["params"]["search"] = search
    if status:
        pagination["params"]["status"] = status
    if sort and sort != "hostname":
        pagination["params"]["sort"] = sort

    ctx = _base_context(
        request,
        active_page="dashboard",
        current_user=current_user,
        servers=servers,
        stats=stats,
        pagination=pagination,
        search=search,
        status_filter=status,
        sort=sort,
    )

    response = templates.TemplateResponse("dashboard.html", ctx)
    if lang and lang in ("ru", "en"):
        response.set_cookie("lang", lang, max_age=31536000)
    return response


@router.get("/servers/{server_id}", response_class=HTMLResponse, include_in_schema=False)
async def server_detail_page(
    request: Request,
    server_id: int,
    lang: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render server detail page."""
    # Stub server data. In production, fetch from database.
    server = {
        "id": server_id,
        "hostname": "server-" + str(server_id),
        "ip": "10.0.0." + str(server_id),
        "status": "online",
        "os_name": "CentOS",
        "os_version": "7.9",
        "kernel": "3.10.0-1160.el7.x86_64",
        "cpu": "Intel Xeon E5-2680 v4",
        "ram": "64 GB",
        "uptime": "45 days",
        "agent_version": "1.0.0",
        "last_seen": datetime.utcnow().isoformat(),
        "last_seen_display": "just now",
        "controllers_count": 1,
        "vd_ok": 2,
        "vd_total": 2,
        "pd_ok": 6,
        "pd_total": 6,
        "active_alerts": 0,
        "recent_events": [],
    }

    ctx = _base_context(
        request,
        active_page="servers",
        current_user=current_user,
        server=server,
    )

    response = templates.TemplateResponse("server_detail.html", ctx)
    if lang and lang in ("ru", "en"):
        response.set_cookie("lang", lang, max_age=31536000)
    return response


@router.get("/alerts", response_class=HTMLResponse, include_in_schema=False)
async def alerts_page(
    request: Request,
    lang: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render alerts page with active alerts."""
    active_alerts = []

    ctx = _base_context(
        request,
        active_page="alerts",
        current_user=current_user,
        active_alerts=active_alerts,
        active_alerts_count=len(active_alerts),
    )

    response = templates.TemplateResponse("alerts.html", ctx)
    if lang and lang in ("ru", "en"):
        response.set_cookie("lang", lang, max_age=31536000)
    return response


@router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings_redirect(request: Request):
    """Redirect /settings to /settings/general."""
    return RedirectResponse(url="/settings/general", status_code=302)


async def _load_settings_dict(db) -> dict:
    """Load all settings from the DB into a dict, decrypting where needed."""
    from app.models.setting import Setting
    result = await db.execute(select(Setting))
    rows = result.scalars().all()

    defaults = {
        "default_language": "en",
        "data_retention_days": "90",
        "agent_auto_approve": "false",
        "ldap_enabled": "false",
        "ldap_server_url": "",
        "ldap_bind_dn": "",
        "ldap_bind_password": "",
        "ldap_search_base": "",
        "ldap_user_filter": "(uid={username})",
        "ldap_group_filter": "",
        "ldap_admin_group": "",
        "telegram_enabled": "false",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "web_debug_enabled": "false",
    }

    for row in rows:
        val = row.value or ""
        if row.is_encrypted and val:
            try:
                from app.services.encryption import decrypt_value
                val = decrypt_value(val)
            except Exception:
                val = ""
        defaults[row.key] = val

    # Convert special types
    out = dict(defaults)
    out["data_retention_days"] = int(out.get("data_retention_days", "90") or "90")
    out["agent_auto_approve"] = out.get("agent_auto_approve", "false").lower() in ("true", "1", "on")
    out["ldap_enabled"] = out.get("ldap_enabled", "false").lower() in ("true", "1", "on")
    out["telegram_enabled"] = out.get("telegram_enabled", "false").lower() in ("true", "1", "on")
    out["web_debug_enabled"] = out.get("web_debug_enabled", "false").lower() in ("true", "1", "on")
    return out


async def _save_setting(db, key: str, value: str, *, encrypted: bool = False, category: str = "general"):
    """Upsert a single setting row."""
    from app.models.setting import Setting
    if encrypted and value:
        from app.services.encryption import encrypt_value
        value = encrypt_value(value)

    result = await db.execute(select(Setting).where(Setting.key == key))
    existing = result.scalar_one_or_none()
    if existing:
        existing.value = value
        existing.is_encrypted = encrypted
        existing.category = category
    else:
        db.add(Setting(key=key, value=value, is_encrypted=encrypted, category=category))


@router.get(
    "/settings/{section}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_page(
    request: Request,
    section: str,
    lang: Optional[str] = None,
    saved: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render settings page for the given section."""
    valid_sections = ("general", "ldap", "telegram", "ssl", "agents", "debug")
    if section not in valid_sections:
        return RedirectResponse(url="/settings/general", status_code=302)

    # Load settings from database
    from app.database import async_session
    async with async_session() as db:
        settings_data = await _load_settings_dict(db)

    extra = {
        "settings": settings_data,
        "settings_section": section,
    }

    if saved == "1":
        lang_code = _get_lang(request)
        _ = _make_gettext(lang_code)
        extra["messages"] = [{"category": "success", "text": _("Settings saved successfully.")}]

    # Section-specific context
    if section == "ssl":
        ssl_info = _get_ssl_info()
        extra["ssl_info"] = ssl_info

    if section == "agents":
        extra["agent_current_version"] = "1.0.0"
        extra["agent_packages"] = []

    if section == "debug":
        extra["agents"] = []

    template_name = f"settings/{section}.html"

    ctx = _base_context(
        request,
        active_page="settings",
        current_user=current_user,
        **extra,
    )

    response = templates.TemplateResponse(template_name, ctx)
    if lang and lang in ("ru", "en"):
        response.set_cookie("lang", lang, max_age=31536000)
    return response


def _get_ssl_info() -> dict:
    """Read SSL certificate info from nginx_ssl volume."""
    import ssl as _ssl
    from datetime import timezone

    cert_path = "/app/nginx_ssl/server.crt"
    if not os.path.exists(cert_path):
        cert_path = "/app/nginx_ssl/cert.pem"
    if not os.path.exists(cert_path):
        return {}

    try:
        import OpenSSL.crypto
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        not_after = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
        not_before = datetime.strptime(cert.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ")
        days_left = (not_after - datetime.utcnow()).days
        return {
            "subject": f"CN={subject.CN}" if subject.CN else str(subject),
            "issuer": f"CN={issuer.CN}" if issuer.CN else str(issuer),
            "valid_from": not_before.strftime("%Y-%m-%d"),
            "valid_to": not_after.strftime("%Y-%m-%d"),
            "days_until_expiry": days_left,
        }
    except Exception:
        # Fallback if pyOpenSSL not available — try subprocess
        try:
            import subprocess
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-dates", "-subject", "-issuer"],
                capture_output=True, text=True, timeout=5,
            )
            info = {}
            for line in result.stdout.strip().splitlines():
                if line.startswith("subject="):
                    info["subject"] = line.split("=", 1)[1].strip()
                elif line.startswith("issuer="):
                    info["issuer"] = line.split("=", 1)[1].strip()
                elif line.startswith("notBefore="):
                    info["valid_from"] = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    info["valid_to"] = line.split("=", 1)[1].strip()
            return info
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Settings POST handlers
# ---------------------------------------------------------------------------

@router.post(
    "/settings/general",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_general_save(
    request: Request,
    current_user: dict = Depends(_require_auth),
    default_language: str = Form("en"),
    data_retention_days: int = Form(90),
    agent_auto_approve: Optional[str] = Form(None),
):
    """Save general settings."""
    from app.database import async_session

    async with async_session() as db:
        await _save_setting(db, "default_language", default_language, category="general")
        await _save_setting(db, "data_retention_days", str(data_retention_days), category="general")
        await _save_setting(db, "agent_auto_approve", "true" if agent_auto_approve else "false", category="general")
        await db.commit()

    return RedirectResponse(url="/settings/general?saved=1", status_code=303)


@router.post(
    "/settings/ldap",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_ldap_save(
    request: Request,
    current_user: dict = Depends(_require_auth),
    ldap_enabled: Optional[str] = Form(None),
    ldap_server_url: str = Form(""),
    ldap_bind_dn: str = Form(""),
    ldap_bind_password: str = Form(""),
    ldap_search_base: str = Form(""),
    ldap_user_filter: str = Form("(uid={username})"),
    ldap_group_filter: str = Form(""),
    ldap_admin_group: str = Form(""),
):
    """Save LDAP settings."""
    from app.database import async_session

    async with async_session() as db:
        await _save_setting(db, "ldap_enabled", "true" if ldap_enabled else "false", category="ldap")
        await _save_setting(db, "ldap_server_url", ldap_server_url, category="ldap")
        await _save_setting(db, "ldap_bind_dn", ldap_bind_dn, category="ldap")
        if ldap_bind_password:
            await _save_setting(db, "ldap_bind_password", ldap_bind_password, encrypted=True, category="ldap")
        await _save_setting(db, "ldap_search_base", ldap_search_base, category="ldap")
        await _save_setting(db, "ldap_user_filter", ldap_user_filter, category="ldap")
        await _save_setting(db, "ldap_group_filter", ldap_group_filter, category="ldap")
        await _save_setting(db, "ldap_admin_group", ldap_admin_group, category="ldap")
        await db.commit()

    return RedirectResponse(url="/settings/ldap?saved=1", status_code=303)


@router.post(
    "/settings/telegram",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_telegram_save(
    request: Request,
    current_user: dict = Depends(_require_auth),
    telegram_enabled: Optional[str] = Form(None),
    telegram_bot_token: str = Form(""),
    telegram_chat_id: str = Form(""),
):
    """Save Telegram notification settings."""
    from app.database import async_session

    async with async_session() as db:
        await _save_setting(db, "telegram_enabled", "true" if telegram_enabled else "false", category="telegram")
        if telegram_bot_token:
            await _save_setting(db, "telegram_bot_token", telegram_bot_token, encrypted=True, category="telegram")
        await _save_setting(db, "telegram_chat_id", telegram_chat_id, category="telegram")
        await db.commit()

    return RedirectResponse(url="/settings/telegram?saved=1", status_code=303)


@router.post(
    "/settings/ssl",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_ssl_upload(
    request: Request,
    current_user: dict = Depends(_require_auth),
    ssl_cert_file: UploadFile = File(None),
    ssl_key_file: UploadFile = File(None),
):
    """Upload SSL certificate and key files."""
    import shutil

    ssl_dir = "/app/nginx_ssl"
    os.makedirs(ssl_dir, exist_ok=True)

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    if ssl_cert_file and ssl_cert_file.filename:
        cert_data = await ssl_cert_file.read()
        with open(os.path.join(ssl_dir, "server.crt"), "wb") as f:
            f.write(cert_data)

    if ssl_key_file and ssl_key_file.filename:
        key_data = await ssl_key_file.read()
        with open(os.path.join(ssl_dir, "server.key"), "wb") as f:
            f.write(key_data)

    return RedirectResponse(url="/settings/ssl?saved=1", status_code=303)


@router.post(
    "/settings/agents/upload",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_agents_upload(
    request: Request,
    current_user: dict = Depends(_require_auth),
    agent_rpm: UploadFile = File(None),
):
    """Upload agent RPM package."""
    if agent_rpm and agent_rpm.filename:
        upload_dir = "/app/agent_packages"
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, agent_rpm.filename)
        data = await agent_rpm.read()
        with open(file_path, "wb") as f:
            f.write(data)

    return RedirectResponse(url="/settings/agents?saved=1", status_code=303)


@router.post(
    "/settings/agents/storcli-upload",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_storcli_upload(
    request: Request,
    current_user: dict = Depends(_require_auth),
    storcli_rpm: UploadFile = File(None),
):
    """Upload storcli64 RPM package."""
    if storcli_rpm and storcli_rpm.filename:
        upload_dir = "/app/storcli_packages"
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, storcli_rpm.filename)
        data = await storcli_rpm.read()
        with open(file_path, "wb") as f:
            f.write(data)

    return RedirectResponse(url="/settings/agents?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# HTMX Partial Routes (for lazy-loaded tab content)
# ---------------------------------------------------------------------------

@router.get(
    "/servers/{server_id}/controllers",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_controllers_partial(
    request: Request,
    server_id: int,
    current_user: dict = Depends(_require_auth),
):
    """Return controllers HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)
    controllers = []

    html_parts = []
    if not controllers:
        html_parts.append(
            f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No controllers found for this server.")}</p>'
            f'</div>'
        )
    else:
        for ctrl in controllers:
            html_parts.append(f'<div class="card border-0 shadow-sm mb-3">')
            html_parts.append(f'<div class="card-body"><pre>{ctrl}</pre></div></div>')

    return HTMLResponse(content="\n".join(html_parts))


@router.get(
    "/servers/{server_id}/virtual-drives",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_vd_partial(
    request: Request,
    server_id: int,
    current_user: dict = Depends(_require_auth),
):
    """Return virtual drives HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = (
        f'<div class="text-center py-5 text-muted">'
        f'<p>{_("No virtual drives found for this server.")}</p>'
        f'</div>'
    )
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/physical-drives",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_pd_partial(
    request: Request,
    server_id: int,
    current_user: dict = Depends(_require_auth),
):
    """Return physical drives HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = (
        f'<div class="text-center py-5 text-muted">'
        f'<p>{_("No physical drives found for this server.")}</p>'
        f'</div>'
    )
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/events",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_events_partial(
    request: Request,
    server_id: int,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    current_user: dict = Depends(_require_auth),
):
    """Return events HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = (
        f'<div class="text-center py-5 text-muted">'
        f'<p>{_("No events found for this server.")}</p>'
        f'</div>'
    )
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/agent",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_agent_partial(
    request: Request,
    server_id: int,
    current_user: dict = Depends(_require_auth),
):
    """Return agent info HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = f"""
    <div class="card border-0 shadow-sm">
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <table class="table table-sm table-borderless mb-0">
              <tr><td class="text-muted">{_("Agent Version")}:</td><td class="fw-semibold">1.0.0</td></tr>
              <tr><td class="text-muted">{_("StorCLI Version")}:</td><td class="fw-semibold">N/A</td></tr>
              <tr><td class="text-muted">{_("Last Seen")}:</td><td class="fw-semibold">N/A</td></tr>
              <tr><td class="text-muted">{_("Registered")}:</td><td class="fw-semibold">N/A</td></tr>
            </table>
          </div>
          <div class="col-md-6">
            <div class="mb-3">
              <label class="form-label fw-semibold">{_("Debug Logging")}</label>
              <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="debugToggle"
                       hx-put="/api/servers/{server_id}/agent/debug"
                       hx-swap="none"
                       hx-vals='js:{{"enabled": event.target.checked}}'>
                <label class="form-check-label" for="debugToggle">{_("Enable debug mode")}</label>
              </div>
            </div>
            <button class="btn btn-outline-primary btn-sm"
                    hx-post="/api/servers/{server_id}/agent/collect-logs"
                    hx-swap="none">
              {_("Collect Logs")}
            </button>
          </div>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(content=html)


@router.get(
    "/alerts/history",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def alerts_history_partial(
    request: Request,
    severity: Optional[str] = None,
    server: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    page: int = Query(1, ge=1),
    current_user: dict = Depends(_require_auth),
):
    """Return alert history HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = f"""
    <div class="card border-0 shadow-sm">
      <div class="card-header bg-white">
        <div class="row g-2 align-items-end">
          <div class="col-auto">
            <label class="form-label small text-muted mb-1">{_("Severity")}</label>
            <select class="form-select form-select-sm" name="severity"
                    hx-get="/alerts/history"
                    hx-target="#alert-history-pane"
                    hx-swap="innerHTML"
                    hx-include="[name='server'],[name='date_from'],[name='date_to']">
              <option value="">{_("All")}</option>
              <option value="critical">{_("Critical")}</option>
              <option value="warning">{_("Warning")}</option>
              <option value="info">{_("Info")}</option>
            </select>
          </div>
          <div class="col-auto">
            <label class="form-label small text-muted mb-1">{_("Server")}</label>
            <select class="form-select form-select-sm" name="server"
                    hx-get="/alerts/history"
                    hx-target="#alert-history-pane"
                    hx-swap="innerHTML"
                    hx-include="[name='severity'],[name='date_from'],[name='date_to']">
              <option value="">{_("All Servers")}</option>
            </select>
          </div>
          <div class="col-auto">
            <label class="form-label small text-muted mb-1">{_("From")}</label>
            <input type="date" class="form-control form-control-sm" name="date_from"
                   hx-get="/alerts/history" hx-target="#alert-history-pane" hx-swap="innerHTML"
                   hx-trigger="change" hx-include="[name='severity'],[name='server'],[name='date_to']">
          </div>
          <div class="col-auto">
            <label class="form-label small text-muted mb-1">{_("To")}</label>
            <input type="date" class="form-control form-control-sm" name="date_to"
                   hx-get="/alerts/history" hx-target="#alert-history-pane" hx-swap="innerHTML"
                   hx-trigger="change" hx-include="[name='severity'],[name='server'],[name='date_from']">
          </div>
        </div>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover table-sm align-middle mb-0">
            <thead class="table-light">
              <tr>
                <th>{_("Time")}</th>
                <th>{_("Severity")}</th>
                <th>{_("Server")}</th>
                <th>{_("Title")}</th>
                <th>{_("Status")}</th>
                <th>{_("Resolved at")}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="6" class="text-center text-muted py-4">{_("No active alerts")}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(content=html)


@router.get(
    "/alerts/rules",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def alerts_rules_partial(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Return alert rules HTML partial for HTMX tab loading."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = f"""
    <div class="card border-0 shadow-sm">
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover table-sm align-middle mb-0">
            <thead class="table-light">
              <tr>
                <th>{_("Name")}</th>
                <th>{_("Category")}</th>
                <th>{_("Severity")}</th>
                <th>{_("Enabled")}</th>
                <th>{_("Cooldown")}</th>
                <th>{_("Telegram")}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="6" class="text-center text-muted py-4">{_("No active alerts")}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/physical-drives/{drive_id}/smart",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_pd_smart_partial(
    request: Request,
    server_id: int,
    drive_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return SMART data HTML partial for modal display."""
    lang = _get_lang(request)
    _ = _make_gettext(lang)

    html = f"""
    <div class="text-center py-4">
      <h6>{_("SMART Data")} - {drive_id}</h6>
      <p class="text-muted">{_("No SMART data available for this drive.")}</p>
    </div>
    """
    return HTMLResponse(content=html)
