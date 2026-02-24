"""
RAID Monitor - Web (HTML) Routes
All Jinja2 template rendering routes for the frontend.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, Depends, Query, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

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
    Stub auth dependency. In production, this would check session/JWT.
    Returns a user dict or None.
    """
    user = getattr(request.state, "user", None)
    if user:
        return user
    # Fallback: check for session cookie (stub)
    session_token = request.cookies.get("session")
    if session_token:
        return {"username": "admin", "id": 1, "is_admin": True}
    return None


async def _require_auth(request: Request) -> dict:
    """Dependency that redirects to login if not authenticated."""
    user = await _get_current_user(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
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


@router.get(
    "/settings/{section}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def settings_page(
    request: Request,
    section: str,
    lang: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render settings page for the given section."""
    valid_sections = ("general", "ldap", "telegram", "ssl", "agents", "debug")
    if section not in valid_sections:
        return RedirectResponse(url="/settings/general", status_code=302)

    # Stub settings data
    settings = {
        "default_language": _get_lang(request),
        "data_retention_days": 90,
        "agent_auto_approve": False,
        "ldap_enabled": False,
        "ldap_server_url": "",
        "ldap_bind_dn": "",
        "ldap_bind_password": "",
        "ldap_search_base": "",
        "ldap_user_filter": "(uid={username})",
        "ldap_group_filter": "",
        "ldap_admin_group": "",
        "telegram_enabled": False,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "web_debug_enabled": False,
    }

    extra = {
        "settings": settings,
        "settings_section": section,
    }

    # Section-specific context
    if section == "ssl":
        extra["ssl_info"] = {
            "subject": "CN=raid-monitor.local",
            "issuer": "CN=raid-monitor.local",
            "valid_from": "2025-01-01",
            "valid_to": "2026-01-01",
            "days_until_expiry": 310,
        }

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
