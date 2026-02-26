"""
RAID Monitor - Web (HTML) Routes
All Jinja2 template rendering routes for the frontend.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path
from app.config import MSK
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
        "Last OS Update": "Последнее обновление ОС",
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
        "No events found for this filter.": "Событий с таким фильтром не найдено.",
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
        "Total": "Всего",
        "Progress": "Прогресс",
        "All Severities": "Все уровни",
        "Error loading events": "Ошибка загрузки событий",
        "of": "из",
        "items": "записей",
        "problem": "проблема",
        "degraded": "деградирован",
        "failed": "неисправен",
        "Controller overheating": "Перегрев контроллера",
        "predictive failure": "предсказанный сбой",
        "uncorrectable memory errors": "некорректируемых ошибок памяти",
        "BBU replacement required": "Требуется замена BBU",
        "alert": "тревога",
        "media errors": "ошибок чтения",
        "overheating": "перегрев",
        "Health": "Состояние",
        "Settings saved successfully.": "Настройки успешно сохранены.",
        "Toggle theme": "Переключить тему",
        "Software RAID": "Программный RAID",
        "Loading software RAID...": "Загрузка программного RAID...",
        "No software RAID arrays found for this server.": "Программные RAID массивы для этого сервера не найдены.",
        "Array": "Массив",
        "Level": "Уровень",
        "Failed": "Отказавшие",
        "Spare": "Запасные",
        "Rebuild Progress": "Прогресс ребилда",
        "Members": "Участники",
        "SMART Status": "Статус SMART",
        "PASSED": "ПРОЙДЕН",
        "FAILED": "НЕ ПРОЙДЕН",
        "Power-On Hours": "Часы работы",
        "Reallocated Sectors": "Переназначенные секторы",
        "Pending Sectors": "Ожидающие секторы",
        "Uncorrectable Sectors": "Неисправимые секторы",
        "Attribute": "Атрибут",
        "Value": "Значение",
        "Worst": "Худшее",
        "Threshold": "Порог",
        "Raw Value": "Сырое значение",
        "No SMART data available for this drive.": "Данные SMART для этого диска недоступны.",
        "SmartCTL Version": "Версия SmartCTL",
        "Device": "Устройство",
        "Capacity": "Объём",
        "Serial Number": "Серийный номер",
        "Power On Hours": "Часы работы",
        "Attributes": "Атрибуты",
        "Flags": "Флаги",
        "Drive not found": "Диск не найден",
        "No SMART data available": "Данные SMART недоступны",
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


def _get_theme(request: Request) -> str:
    """Determine theme from query param, cookie, or default."""
    theme = request.query_params.get("theme")
    if theme in ("light", "dark"):
        return theme
    theme = request.cookies.get("theme")
    if theme in ("light", "dark"):
        return theme
    return "light"


def _base_context(request: Request, active_page: str = "", **extra) -> dict:
    """Build base template context with common variables."""
    lang = _get_lang(request)
    theme = _get_theme(request)
    ctx = {
        "request": request,
        "lang": lang,
        "theme": theme,
        "_": _make_gettext(lang),
        "active_page": active_page,
        "csrf_token": request.cookies.get("csrf_token", ""),
        "version": "1.1.6",
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
                from app.services.ldap_auth import authenticate_ldap
                ldap_result = await authenticate_ldap(username, password)
                if ldap_result:
                    if user is None:
                        user = User(
                            username=username,
                            display_name=ldap_result.get("display_name", username),
                            email=ldap_result.get("email") or None,
                            auth_source="ldap",
                            is_active=True,
                            is_admin=ldap_result.get("is_admin", False),
                            language=lang,
                        )
                        db.add(user)
                    else:
                        user.display_name = ldap_result.get("display_name") or user.display_name
                        user.email = ldap_result.get("email") or user.email
                        user.auth_source = "ldap"
                        user.is_admin = ldap_result.get("is_admin", False)
                    user.last_login = datetime.now(MSK)
                    await db.commit()
                    await db.refresh(user)
                    authenticated = True
            except Exception as exc:
                logger.exception("LDAP authentication error: %s", exc)

        if not authenticated:
            ctx = _base_context(request, active_page="login", error=_("Invalid credentials"))
            return templates.TemplateResponse("login.html", ctx)

        # Create JWT token
        expire = datetime.now(MSK) + timedelta(hours=24)
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
        response.set_cookie("theme", getattr(user, "theme", None) or "light", max_age=31536000)
        return response


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear auth cookie and redirect to login."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


@router.post("/set-preference", include_in_schema=False)
async def set_preference(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Save user preference (lang or theme) to DB and cookie."""
    from app.database import async_session
    from app.models.user import User

    data = await request.json()
    key = data.get("key")
    value = data.get("value")

    if key == "lang" and value in ("ru", "en"):
        pass
    elif key == "theme" and value in ("light", "dark"):
        pass
    else:
        raise HTTPException(status_code=400, detail="Invalid preference")

    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == current_user["username"]))
        user = result.scalar_one_or_none()
        if user:
            setattr(user, "language" if key == "lang" else key, value)
            await db.commit()

    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True})
    response.set_cookie(key, value, max_age=31536000)
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
    from app.database import async_session
    from app.models.server import Server
    from app.models.controller import Controller
    from app.models.virtual_drive import VirtualDrive
    from app.models.physical_drive import PhysicalDrive
    from sqlalchemy import func
    from sqlalchemy.orm import selectinload

    _ = _make_gettext(_get_lang(request))

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

    per_page = 24
    async with async_session() as db:
        # Build query with filters
        query = select(Server).options(
            selectinload(Server.controllers).selectinload(Controller.virtual_drives),
            selectinload(Server.controllers).selectinload(Controller.physical_drives),
            selectinload(Server.controllers).selectinload(Controller.bbu),
        )
        if search:
            query = query.where(
                Server.hostname.ilike(f"%{search}%")
                | Server.ip_address.ilike(f"%{search}%")
            )
        if status:
            query = query.where(Server.status == status)

        # Count total
        count_q = select(func.count(Server.id))
        if search:
            count_q = count_q.where(
                Server.hostname.ilike(f"%{search}%")
                | Server.ip_address.ilike(f"%{search}%")
            )
        if status:
            count_q = count_q.where(Server.status == status)
        total_items = (await db.execute(count_q)).scalar() or 0

        # Sort
        sort_col = {
            "hostname": Server.hostname,
            "status": Server.status,
            "last_seen": Server.last_seen,
            "ip": Server.ip_address,
        }.get(sort, Server.hostname)
        query = query.order_by(sort_col)

        # Paginate
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)

        result = await db.execute(query)
        db_servers = result.unique().scalars().all()

        # Build template-friendly server dicts
        for srv in db_servers:
            ctrl_count = len(srv.controllers) if srv.controllers else 0
            vd_total = 0
            vd_ok = 0
            pd_total = 0
            pd_ok = 0
            for ctrl in (srv.controllers or []):
                for vd in (ctrl.virtual_drives or []):
                    vd_total += 1
                    if vd.state and vd.state.lower() in ("optimal", "optl"):
                        vd_ok += 1
                for pd in (ctrl.physical_drives or []):
                    pd_total += 1
                    if pd.state and pd.state.lower() in ("online", "onln", "ugood", "jbod", "ghs", "dhs"):
                        pd_ok += 1

            # Build health status summary
            health_issues = []
            vd_bad = vd_total - vd_ok
            pd_bad = pd_total - pd_ok
            if vd_bad > 0:
                health_issues.append(f"VD: {vd_bad} " + _("degraded"))
            if pd_bad > 0:
                health_issues.append(f"PD: {pd_bad} " + _("failed"))
            for ctrl in (srv.controllers or []):
                # Controller status
                if ctrl.status and ctrl.status.lower() not in ("optimal", "opt", ""):
                    health_issues.append(f"Ctrl#{ctrl.controller_id}: {ctrl.status}")
                # Controller overheating
                if ctrl.roc_temperature and ctrl.roc_temperature > 80:
                    health_issues.append(_("Controller overheating") + f" ({ctrl.roc_temperature}C)")
                # Memory uncorrectable errors
                if (ctrl.memory_uncorrectable_errors or 0) > 0:
                    health_issues.append(f"Ctrl#{ctrl.controller_id}: {ctrl.memory_uncorrectable_errors} " + _("uncorrectable memory errors"))
                # ECC bucket count
                if (ctrl.ecc_bucket_count or 0) > 0:
                    health_issues.append(f"Ctrl#{ctrl.controller_id}: ECC bucket {ctrl.ecc_bucket_count}")
                # BBU / CacheVault
                if ctrl.bbu:
                    bbu_state = (ctrl.bbu.state or "").lower()
                    if bbu_state and bbu_state not in ("optimal", "opt", "ready", ""):
                        health_issues.append(f"BBU: {ctrl.bbu.state}")
                    if ctrl.bbu.replacement_needed:
                        health_issues.append(_("BBU replacement required"))
                # Physical drives
                for pd in (ctrl.physical_drives or []):
                    # Predictive failure
                    if (pd.predictive_failure or 0) > 0:
                        health_issues.append(f"PD {pd.enclosure_id}:{pd.slot_number} " + _("predictive failure"))
                    # SMART alert
                    if pd.smart_alert:
                        health_issues.append(f"PD {pd.enclosure_id}:{pd.slot_number} SMART " + _("alert"))
                    # Media errors
                    if (pd.media_error_count or 0) > 0:
                        health_issues.append(f"PD {pd.enclosure_id}:{pd.slot_number}: {pd.media_error_count} " + _("media errors"))
                    # Drive overheating
                    if pd.temperature and pd.temperature > 55:
                        health_issues.append(f"PD {pd.enclosure_id}:{pd.slot_number} " + _("overheating") + f" ({pd.temperature}C)")
            # Deduplicate while preserving order
            seen = set()
            unique_issues = []
            for issue in health_issues:
                if issue not in seen:
                    seen.add(issue)
                    unique_issues.append(issue)
            health_status = "; ".join(unique_issues) if unique_issues else "OK"

            servers.append({
                "id": str(srv.id),
                "hostname": srv.hostname,
                "ip": srv.ip_address,
                "status": srv.status or "unknown",
                "os_name": srv.os_name,
                "os_version": srv.os_version,
                "agent_version": srv.agent_version,
                "last_seen": srv.last_seen.isoformat() if srv.last_seen else "",
                "last_seen_display": srv.last_seen.strftime("%d.%m %H:%M") if srv.last_seen else "N/A",
                "controllers_count": ctrl_count,
                "vd_total": vd_total,
                "vd_ok": vd_ok,
                "pd_total": pd_total,
                "pd_ok": pd_ok,
                "health_status": health_status,
            })

            # Accumulate global stats
            stats["controllers_total"] += ctrl_count
            stats["vd_total"] += vd_total
            stats["vd_ok"] += vd_ok
            stats["pd_total"] += pd_total
            stats["pd_ok"] += pd_ok

        # Global server stats (unfiltered)
        total_servers = (await db.execute(select(func.count(Server.id)))).scalar() or 0
        online_servers = (await db.execute(
            select(func.count(Server.id)).where(Server.status == "online")
        )).scalar() or 0

        stats["servers_total"] = total_servers
        stats["servers_online"] = online_servers
        stats["vd_problem"] = stats["vd_total"] - stats["vd_ok"]
        stats["pd_problem"] = stats["pd_total"] - stats["pd_ok"]

    import math
    total_pages = max(1, math.ceil(total_items / per_page))
    pagination = {
        "current_page": page,
        "total_pages": total_pages,
        "total_items": total_items,
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
    server_id: str,
    lang: Optional[str] = None,
    current_user: dict = Depends(_require_auth),
):
    """Render server detail page."""
    from app.database import async_session
    from app.models.server import Server
    from app.models.controller import Controller
    from app.models.virtual_drive import VirtualDrive
    from app.models.physical_drive import PhysicalDrive
    from app.models.bbu import BbuUnit
    from sqlalchemy.orm import selectinload

    from app.models.software_raid import SoftwareRaid as SoftwareRaidModel

    async with async_session() as db:
        result = await db.execute(
            select(Server).where(Server.id == server_id).options(
                selectinload(Server.controllers).selectinload(Controller.virtual_drives),
                selectinload(Server.controllers).selectinload(Controller.physical_drives),
                selectinload(Server.controllers).selectinload(Controller.bbu),
                selectinload(Server.software_raids),
            )
        )
        srv = result.unique().scalar_one_or_none()
        if not srv:
            raise HTTPException(status_code=404, detail="Server not found")

    vd_total = vd_ok = pd_total = pd_ok = 0
    controllers_list = []
    all_vds = []
    all_pds = []
    for ctrl in (srv.controllers or []):
        for vd in (ctrl.virtual_drives or []):
            vd_total += 1
            if vd.state and vd.state.lower() in ("optimal", "optl"):
                vd_ok += 1
            all_vds.append(vd)
        for pd in (ctrl.physical_drives or []):
            pd_total += 1
            if pd.state and pd.state.lower() in ("online", "onln", "ugood", "jbod", "ghs", "dhs"):
                pd_ok += 1
            all_pds.append(pd)
        bbu_info = None
        if ctrl.bbu:
            is_cv = ctrl.bbu.bbu_type and ctrl.bbu.bbu_type.upper().startswith("CVPM")
            bbu_info = {
                "status": ctrl.bbu.state or "N/A",
                "type": ctrl.bbu.bbu_type or "N/A",
                "temperature": ctrl.bbu.temperature,
                "charge": (ctrl.bbu.capacitance or "N/A") if is_cv else (ctrl.bbu.remaining_capacity or "N/A"),
                "capacitance": ctrl.bbu.capacitance or "",
                "pack_energy": ctrl.bbu.pack_energy or "",
                "design_capacity": ctrl.bbu.design_capacity or "",
                "manufacture_date": ctrl.bbu.manufacture_date or "",
                "flash_size": ctrl.bbu.flash_size or "",
                "replacement_needed": ctrl.bbu.replacement_needed,
            }
        controllers_list.append({
            "id": ctrl.controller_id,
            "model": ctrl.model,
            "serial": ctrl.serial_number,
            "firmware": ctrl.firmware_version,
            "bios_version": ctrl.bios_version,
            "driver_version": ctrl.driver_version,
            "status": ctrl.status,
            "temperature": ctrl.roc_temperature,
            "rebuild_rate": ctrl.rebuild_rate,
            "patrol_read": ctrl.patrol_read_status,
            "cc_status": ctrl.cc_status,
            "alarm": ctrl.alarm_status,
            "memory_size": ctrl.memory_size,
            "memory_correctable_errors": ctrl.memory_correctable_errors or 0,
            "memory_uncorrectable_errors": ctrl.memory_uncorrectable_errors or 0,
            "host_interface": ctrl.host_interface or "",
            "product_name": ctrl.product_name or "",
            "supported_raid_levels": ctrl.supported_raid_levels or [],
            "next_cc_launch": ctrl.next_cc_launch or "",
            "next_pr_launch": ctrl.next_pr_launch or "",
            "next_battery_learn": ctrl.next_battery_learn or "",
            "ecc_bucket_count": ctrl.ecc_bucket_count or 0,
            "firmware_package_build": ctrl.firmware_package_build or "",
            "driver_name": ctrl.driver_name or "",
            "bbu": bbu_info,
        })

    # Count smartctl drives — exclude MegaRAID-managed drives when controllers exist
    smart_drives_list = (srv.last_report or {}).get("smart_drives") or []
    if smart_drives_list:
        if controllers_list:
            # Filter out drives behind MegaRAID and controller VDs
            _RC_KW = ("avago", "lsi", "megaraid", "perc", "broadcom")
            smart_drives_list = [
                d for d in smart_drives_list
                if "megaraid" not in (d.get("scan_type") or "").lower()
                and not any(kw in (d.get("model") or "").lower() for kw in _RC_KW)
            ]
        if smart_drives_list:
            smart_total = len(smart_drives_list)
            smart_ok = sum(1 for d in smart_drives_list if d.get("smart_status") is not False)
            if smart_total > pd_total:
                pd_total = smart_total
                pd_ok = smart_ok

    uptime_str = "N/A"
    if srv.uptime_seconds:
        days = srv.uptime_seconds // 86400
        hours = (srv.uptime_seconds % 86400) // 3600
        uptime_str = f"{days}d {hours}h"

    ram_str = f"{srv.ram_total_gb:.0f} GB" if srv.ram_total_gb else "N/A"

    server = {
        "id": str(srv.id),
        "hostname": srv.hostname,
        "ip": srv.ip_address,
        "status": srv.status or "unknown",
        "os_name": srv.os_name,
        "os_version": srv.os_version,
        "kernel": srv.kernel_version,
        "cpu": srv.cpu_model or "N/A",
        "ram": ram_str,
        "uptime": uptime_str,
        "agent_version": srv.agent_version,
        "last_os_update": srv.last_os_update or "N/A",
        "last_seen": srv.last_seen.isoformat() if srv.last_seen else "",
        "last_seen_display": srv.last_seen.strftime("%d.%m %H:%M") if srv.last_seen else "N/A",
        "controllers_count": len(srv.controllers or []),
        "vd_ok": vd_ok,
        "vd_total": vd_total,
        "pd_ok": pd_ok,
        "pd_total": pd_total,
        "swraid_count": len(srv.software_raids or []),
        "swraid_degraded": sum(
            1 for sr in (srv.software_raids or [])
            if sr.state and sr.state.lower() in ("degraded", "inactive", "rebuilding")
        ),
        "active_alerts": 0,
        "recent_events": [],
    }

    # Build VD list for template
    virtual_drives = []
    for vd in all_vds:
        virtual_drives.append({
            "dg": vd.dg_id, "vd": vd.vd_id, "name": vd.name,
            "raid_type": vd.raid_type, "state": vd.state, "size": vd.size,
            "cache": vd.cache_policy, "io_policy": vd.io_policy,
            "read_policy": vd.read_policy, "drives_count": vd.number_of_drives or 0,
            "active_operations": vd.active_operations or "None",
            "write_cache": vd.write_cache or "",
            "span_depth": vd.span_depth,
        })

    # Build PD list for template
    physical_drives = []
    for pd in all_pds:
        physical_drives.append({
            "eid": pd.enclosure_id, "slot": pd.slot_number, "dg": pd.drive_group,
            "state": pd.state, "size": pd.size, "model": pd.model,
            "serial": pd.serial_number, "firmware": pd.firmware_version,
            "media_type": pd.media_type, "interface": pd.interface_type,
            "temperature": pd.temperature, "media_errors": pd.media_error_count,
            "other_errors": pd.other_error_count, "predictive_failure": pd.predictive_failure,
            "smart_alert": pd.smart_alert,
            "link_speed": pd.link_speed or "",
            "device_speed": pd.device_speed or "",
            "physical_sector_size": pd.physical_sector_size or "",
            "wwn": pd.wwn or "",
        })

    ctx = _base_context(
        request,
        active_page="servers",
        current_user=current_user,
        server=server,
        controllers=controllers_list,
        virtual_drives=virtual_drives,
        physical_drives=physical_drives,
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
        # Load agent packages from database
        from app.models.agent_package import AgentPackage
        async with async_session() as db:
            result = await db.execute(
                select(AgentPackage).order_by(AgentPackage.uploaded_at.desc())
            )
            packages = result.scalars().all()
            current_version = "N/A"
            pkg_list = []
            for pkg in packages:
                if pkg.is_current:
                    current_version = pkg.version
                pkg_list.append({
                    "id": str(pkg.id),
                    "version": pkg.version,
                    "filename": pkg.filename,
                    "size": _format_file_size(pkg.file_size) if pkg.file_size else "",
                    "uploaded_at": pkg.uploaded_at.strftime("%d.%m.%Y %H:%M") if pkg.uploaded_at else "",
                    "is_current": pkg.is_current,
                })
            extra["agent_current_version"] = current_version
            extra["agent_packages"] = pkg_list

        # Load StorCLI packages from filesystem
        storcli_dir = "/app/storcli_packages"
        storcli_packages = []
        if os.path.exists(storcli_dir):
            for fname in sorted(os.listdir(storcli_dir), reverse=True):
                if fname.endswith(".rpm"):
                    fpath = os.path.join(storcli_dir, fname)
                    fstat = os.stat(fpath)
                    storcli_packages.append({
                        "filename": fname,
                        "size": _format_file_size(fstat.st_size),
                        "uploaded_at": datetime.fromtimestamp(fstat.st_mtime, tz=MSK).strftime("%d.%m.%Y %H:%M"),
                    })
        extra["storcli_packages"] = storcli_packages

    if section == "debug":
        # Load real agent list from servers table
        from app.models.server import Server
        async with async_session() as db:
            result = await db.execute(select(Server).order_by(Server.hostname.asc()))
            servers = result.scalars().all()
            agents_list = []
            log_status_list = []
            for srv in servers:
                info = srv.server_info or {}
                agents_list.append({
                    "server_id": srv.id,
                    "hostname": srv.hostname,
                    "ip": srv.ip_address,
                    "status": srv.status,
                    "agent_version": srv.agent_version or "N/A",
                    "debug_enabled": srv.debug_mode if hasattr(srv, 'debug_mode') else info.get("debug_enabled", False),
                })

                # Build log request status for this agent
                pending_cmds = info.get("pending_commands", [])
                executed_cmds = info.get("executed_commands", [])

                # Find latest upload_logs command in pending
                pending_log_cmd = None
                for cmd in reversed(pending_cmds):
                    if cmd.get("type") == "upload_logs":
                        pending_log_cmd = cmd
                        break

                # Find latest upload_logs command in executed
                executed_log_cmd = None
                for cmd in reversed(executed_cmds):
                    if cmd.get("type") == "upload_logs":
                        executed_log_cmd = cmd
                        break

                # Check local log files
                agent_logs_dir = Path("/app/uploads/agent_logs") / str(srv.id)
                log_files_count = 0
                latest_log_time = None
                if agent_logs_dir.exists():
                    for f in agent_logs_dir.iterdir():
                        if f.is_file():
                            log_files_count += 1
                            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=MSK)
                            if latest_log_time is None or mtime > latest_log_time:
                                latest_log_time = mtime

                # Determine status
                if pending_log_cmd:
                    log_req_status = "pending"
                    log_req_time = pending_log_cmd.get("created_at", "")
                elif executed_log_cmd:
                    log_req_status = "completed"
                    log_req_time = executed_log_cmd.get("acked_at", executed_log_cmd.get("created_at", ""))
                else:
                    log_req_status = "none"
                    log_req_time = ""

                log_status_list.append({
                    "server_id": srv.id,
                    "hostname": srv.hostname,
                    "ip": srv.ip_address,
                    "status": srv.status,
                    "log_request_status": log_req_status,
                    "log_request_time": log_req_time,
                    "log_files_count": log_files_count,
                    "latest_log_time": latest_log_time.strftime("%d.%m.%Y %H:%M") if latest_log_time else "",
                })

            extra["agents"] = agents_list
            extra["log_status"] = log_status_list

        # Read last N lines of server log for display
        log_path = os.environ.get("LOG_FILE", "/app/logs/server.log")
        log_lines = ""
        try:
            if os.path.exists(log_path):
                with open(log_path, "r", errors="replace") as f:
                    all_lines = f.readlines()
                    log_lines = "".join(all_lines[-200:])
        except Exception:
            log_lines = "Could not read log file"
        extra["server_log"] = log_lines
        extra["server_log_path"] = log_path

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


def _format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def _get_ssl_info() -> dict:
    """Read SSL certificate info from nginx_ssl volume."""
    import ssl as _ssl

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
        not_after = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=MSK)
        not_before = datetime.strptime(cert.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=MSK)
        days_left = (not_after - datetime.now(MSK)).days
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
    """Upload agent RPM package and register in database."""
    import hashlib
    import re as _re
    from app.database import async_session
    from app.models.agent_package import AgentPackage

    if agent_rpm and agent_rpm.filename:
        upload_dir = "/app/agent_packages"
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, agent_rpm.filename)
        data = await agent_rpm.read()
        with open(file_path, "wb") as f:
            f.write(data)

        # Extract version from filename (e.g. raid-agent-1.0.0-1.el8.x86_64.rpm)
        version_match = _re.search(r"raid-agent-(\d+\.\d+\.\d+)", agent_rpm.filename)
        version = version_match.group(1) if version_match else "unknown"

        sha256 = hashlib.sha256(data).hexdigest()

        async with async_session() as db:
            # Check if this version already exists
            existing = await db.execute(
                select(AgentPackage).where(AgentPackage.version == version)
            )
            pkg = existing.scalar_one_or_none()
            if pkg:
                # Update existing entry
                pkg.filename = agent_rpm.filename
                pkg.file_path = file_path
                pkg.file_hash_sha256 = sha256
                pkg.file_size = len(data)
            else:
                # Mark all others as not current
                all_pkgs = await db.execute(select(AgentPackage))
                for p in all_pkgs.scalars().all():
                    p.is_current = False

                pkg = AgentPackage(
                    version=version,
                    filename=agent_rpm.filename,
                    file_path=file_path,
                    file_hash_sha256=sha256,
                    file_size=len(data),
                    is_current=True,
                )
                db.add(pkg)
            await db.commit()

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


@router.get(
    "/settings/agents/download/{package_id}",
    include_in_schema=False,
)
async def download_agent_package(
    package_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Download an agent RPM package by ID (web UI, requires auth)."""
    from app.database import async_session
    from app.models.agent_package import AgentPackage
    from fastapi.responses import FileResponse

    async with async_session() as db:
        result = await db.execute(select(AgentPackage).where(AgentPackage.id == package_id))
        pkg = result.scalar_one_or_none()
        if not pkg or not os.path.exists(pkg.file_path):
            raise HTTPException(status_code=404, detail="Package not found")
        return FileResponse(
            path=pkg.file_path,
            filename=pkg.filename,
            media_type="application/x-rpm",
        )


@router.get(
    "/api/v1/agent/package/latest",
    include_in_schema=False,
)
async def download_agent_package_latest():
    """Download the current (latest) agent RPM package. No auth required — used by update scripts on agents."""
    from app.database import async_session
    from app.models.agent_package import AgentPackage
    from fastapi.responses import FileResponse

    async with async_session() as db:
        result = await db.execute(
            select(AgentPackage).where(AgentPackage.is_current == True).limit(1)
        )
        pkg = result.scalar_one_or_none()
        if not pkg or not os.path.exists(pkg.file_path):
            raise HTTPException(status_code=404, detail="No current agent package available")
        return FileResponse(
            path=pkg.file_path,
            filename=pkg.filename,
            media_type="application/x-rpm",
        )


@router.get(
    "/api/v1/agent/package/version",
    include_in_schema=False,
)
async def agent_package_version():
    """Return current agent package version. No auth — used by update scripts."""
    from app.database import async_session
    from app.models.agent_package import AgentPackage

    async with async_session() as db:
        result = await db.execute(
            select(AgentPackage).where(AgentPackage.is_current == True).limit(1)
        )
        pkg = result.scalar_one_or_none()
        if not pkg:
            return {"version": None, "filename": None}
        return {
            "version": pkg.version,
            "filename": pkg.filename,
            "sha256": pkg.file_hash_sha256,
            "size": pkg.file_size,
        }


# ---------------------------------------------------------------------------
# HTMX API endpoints (called by hx-put / hx-post in templates)
# These bridge the gap between template URLs (/api/settings/...)
# and the v1 API (/api/v1/settings/...).
# ---------------------------------------------------------------------------

@router.put("/api/settings/debug/web", include_in_schema=False)
async def api_debug_web_toggle(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Toggle web debug logging via HTMX."""
    from app.database import async_session

    form = await request.form()
    enabled = form.get("enabled", "false").lower() in ("true", "1")

    async with async_session() as db:
        await _save_setting(db, "web_debug_enabled", "true" if enabled else "false", category="debug")
        await db.commit()

    # Apply debug level to root logger (all components) + SQL
    import logging as _logging
    level = _logging.DEBUG if enabled else _logging.INFO
    _logging.getLogger().setLevel(level)  # root logger — all components
    _logging.getLogger("sqlalchemy.engine").setLevel(level)  # SQL queries
    _logging.getLogger("sqlalchemy.pool").setLevel(level)
    _logging.getLogger("uvicorn").setLevel(level)
    _logging.getLogger("uvicorn.error").setLevel(level)
    # Keep access log at WARNING to avoid spam
    _logging.getLogger("uvicorn.access").setLevel(_logging.WARNING)

    # Return HTML status badge for HTMX swap
    if enabled:
        badge = (
            '<span class="badge bg-warning text-dark" id="debug-status-badge">'
            '<i class="bi bi-bug-fill me-1"></i>DEBUG</span>'
        )
    else:
        badge = (
            '<span class="badge bg-secondary" id="debug-status-badge">'
            'INFO</span>'
        )
    return HTMLResponse(badge)


@router.post("/api/settings/debug/collect-all", include_in_schema=False)
async def api_debug_collect_all(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Request log collection from all online agents."""
    from app.database import async_session
    from app.models.server import Server
    import secrets as _secrets
    import shutil

    # Delete ALL existing agent logs before requesting fresh ones
    logs_base = Path("/app/uploads/agent_logs")
    if logs_base.exists():
        total_cleaned = 0
        for subdir in logs_base.iterdir():
            if subdir.is_dir():
                for f in subdir.iterdir():
                    if f.is_file():
                        try:
                            f.unlink()
                            total_cleaned += 1
                        except OSError:
                            pass
        if total_cleaned:
            logger.info("Deleted %d old agent log files before collection", total_cleaned)

    async with async_session() as db:
        result = await db.execute(select(Server).where(Server.status == "online"))
        servers = result.scalars().all()
        count = 0
        for srv in servers:
            cmd_id = _secrets.token_hex(8)
            server_info = srv.server_info or {}
            pending = server_info.get("pending_commands", [])
            pending.append({
                "id": cmd_id,
                "type": "upload_logs",
                "created_at": datetime.now(MSK).isoformat(),
            })
            server_info["pending_commands"] = pending
            srv.server_info = server_info
            count += 1
        await db.commit()

    return {"success": True, "message": f"Log collection requested from {count} server(s)"}


@router.post("/api/settings/debug/upload-logs", include_in_schema=False)
async def api_debug_upload_logs(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Upload collected agent logs to file server."""
    import httpx
    import tempfile
    import tarfile

    logs_dir = "/app/uploads/agent_logs"
    if not os.path.exists(logs_dir) or not os.listdir(logs_dir):
        return {"success": False, "message": "No agent logs found to upload"}

    timestamp = datetime.now(MSK).strftime("%Y%m%d_%H%M%S")
    archive_name = f"agent_logs_{timestamp}.tar.gz"

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        with tarfile.open(tmp_path, "w:gz") as tar:
            tar.add(logs_dir, arcname="agent_logs")

        with open(tmp_path, "rb") as f:
            file_data = f.read()
        async with httpx.AsyncClient(timeout=120, verify=False) as client:
            resp = await client.post(
                "https://private-ai.tools/upload",
                files={"file": (archive_name, file_data, "application/gzip")},
            )

        if resp.status_code == 200:
            try:
                resp_data = resp.json()
                download_url = resp_data.get("url", f"https://private-ai.tools/files/{resp_data.get('filename', archive_name)}")
            except Exception:
                download_url = f"https://private-ai.tools/files/{archive_name}"
            return {"success": True, "message": f"Logs uploaded", "url": download_url}
        else:
            return {"success": False, "message": f"Upload failed: HTTP {resp.status_code} — {resp.text[:200]}"}
    except Exception as e:
        logger.exception("Failed to upload agent logs")
        return {"success": False, "message": f"Upload error: {e}"}
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.post("/api/settings/debug/upload-server-log", include_in_schema=False)
async def api_debug_upload_server_log(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Upload server web log to file server and return download link."""
    import httpx

    log_path = os.environ.get("LOG_FILE", "/app/logs/server.log")
    if not os.path.exists(log_path):
        return {"success": False, "message": f"Log file not found: {log_path}"}

    timestamp = datetime.now(MSK).strftime("%Y%m%d_%H%M%S")
    upload_name = f"server_log_{timestamp}.log"

    try:
        with open(log_path, "rb") as f:
            file_data = f.read()
        async with httpx.AsyncClient(timeout=120, verify=False) as client:
            resp = await client.post(
                "https://private-ai.tools/upload",
                files={"file": (upload_name, file_data, "text/plain")},
            )

        if resp.status_code == 200:
            try:
                resp_data = resp.json()
                download_url = resp_data.get("url", f"https://private-ai.tools/files/{resp_data.get('filename', upload_name)}")
            except Exception:
                download_url = f"https://private-ai.tools/files/{upload_name}"
            return {"success": True, "message": f"Server log uploaded", "url": download_url}
        else:
            return {"success": False, "message": f"Upload failed: HTTP {resp.status_code} — {resp.text[:200]}"}
    except Exception as e:
        logger.exception("Failed to upload server log")
        return {"success": False, "message": f"Upload error: {e}"}


@router.post("/api/settings/ldap/test", include_in_schema=False)
async def api_ldap_test(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Test LDAP connection from form data."""
    form = await request.form()
    server_url = form.get("ldap_server_url", "")
    bind_dn = form.get("ldap_bind_dn", "")
    bind_password = form.get("ldap_bind_password", "")
    search_base = form.get("ldap_search_base", "")

    if not server_url:
        return HTMLResponse('<div class="alert alert-danger">LDAP server URL not configured</div>')

    try:
        import ldap3
        server = ldap3.Server(server_url, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password or "", auto_bind=True)
        conn.unbind()
        return HTMLResponse('<div class="alert alert-success">LDAP connection successful</div>')
    except ImportError:
        return HTMLResponse('<div class="alert alert-warning">ldap3 library is not installed</div>')
    except Exception as e:
        return HTMLResponse(f'<div class="alert alert-danger">LDAP error: {e}</div>')


@router.post("/api/settings/telegram/test", include_in_schema=False)
async def api_telegram_test(
    request: Request,
    current_user: dict = Depends(_require_auth),
):
    """Send a test Telegram message from form data."""
    import httpx

    form = await request.form()
    bot_token = form.get("telegram_bot_token", "")
    chat_id = form.get("telegram_chat_id", "")

    if not bot_token:
        return HTMLResponse('<div class="alert alert-danger">Bot token not configured</div>')
    if not chat_id:
        return HTMLResponse('<div class="alert alert-danger">Chat ID not configured</div>')

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id,
                "text": "RAID Monitor: Test notification",
                "parse_mode": "HTML",
            })
        if resp.status_code == 200 and resp.json().get("ok"):
            return HTMLResponse('<div class="alert alert-success">Test message sent successfully</div>')
        else:
            error_desc = resp.json().get("description", resp.text)
            return HTMLResponse(f'<div class="alert alert-danger">Telegram API error: {error_desc}</div>')
    except Exception as e:
        return HTMLResponse(f'<div class="alert alert-danger">Failed to send: {e}</div>')


@router.put("/api/servers/{server_id}/agent/debug", include_in_schema=False)
async def api_agent_debug_toggle(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Toggle debug mode on a specific agent."""
    from app.database import async_session
    from app.models.server import Server
    import secrets as _secrets

    form = await request.form()
    enabled = form.get("enabled", "false").lower() in ("true", "1")

    async with async_session() as db:
        result = await db.execute(select(Server).where(Server.id == server_id))
        server = result.scalar_one_or_none()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")

        # Update debug_mode flag on server record
        server.debug_mode = enabled

        # Send update_config command to agent (agent handles "update_config" type)
        server_info = server.server_info or {}
        pending = server_info.get("pending_commands", [])
        pending.append({
            "id": _secrets.token_hex(8),
            "type": "update_config",
            "params": {"debug": enabled},
            "created_at": datetime.now(MSK).isoformat(),
        })
        server_info["pending_commands"] = pending
        server.server_info = server_info
        await db.commit()

    return {"success": True, "enabled": enabled}


@router.post("/api/servers/{server_id}/agent/collect-logs", include_in_schema=False)
async def api_agent_collect_logs(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Request log collection from a specific agent."""
    from app.database import async_session
    from app.models.server import Server
    import secrets as _secrets

    # Delete existing logs for this agent before requesting fresh ones
    agent_logs_dir = Path("/app/uploads/agent_logs") / server_id
    if agent_logs_dir.exists():
        for f in agent_logs_dir.iterdir():
            if f.is_file():
                try:
                    f.unlink()
                except OSError:
                    pass

    async with async_session() as db:
        result = await db.execute(select(Server).where(Server.id == server_id))
        server = result.scalar_one_or_none()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")

        server_info = server.server_info or {}
        pending = server_info.get("pending_commands", [])
        pending.append({
            "id": _secrets.token_hex(8),
            "type": "upload_logs",
            "created_at": datetime.now(MSK).isoformat(),
        })
        server_info["pending_commands"] = pending
        server.server_info = server_info
        await db.commit()

    return {"success": True, "message": "Log collection requested"}


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
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return controllers HTML partial for HTMX tab loading."""
    from app.database import async_session
    from app.models.controller import Controller
    from app.models.bbu import BbuUnit
    from sqlalchemy.orm import selectinload

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(
            select(Controller)
            .where(Controller.server_id == server_id)
            .options(selectinload(Controller.bbu))
            .order_by(Controller.controller_id)
        )
        ctrls = result.scalars().all()

    if not ctrls:
        return HTMLResponse(
            f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No controllers found for this server.")}</p></div>'
        )

    html_parts = []
    for ctrl in ctrls:
        temp = ctrl.roc_temperature or 0
        temp_badge = "bg-danger" if temp > 80 else ("bg-warning text-dark" if temp > 60 else "bg-success")
        temp_bar = "bg-danger" if temp > 80 else ("bg-warning" if temp > 60 else "bg-success")
        status_badge = "bg-success" if ctrl.status and ctrl.status.lower() in ("optimal", "opt") else (
            "bg-warning text-dark" if ctrl.status and ctrl.status.lower() in ("degraded", "dgrd") else "bg-danger"
        )
        bbu_html = ""
        if ctrl.bbu:
            b = ctrl.bbu
            bbu_status_badge = "bg-success" if b.state and b.state.lower() in ("optimal", "opt") else "bg-warning text-dark"
            # Determine charge display: for CacheVault use capacitance, for BBU use remaining_capacity
            is_cachevault = b.bbu_type and b.bbu_type.upper().startswith("CVPM")
            if is_cachevault:
                charge_display = b.capacitance or "N/A"
            else:
                charge_display = b.remaining_capacity or "N/A"
            bbu_extra = ""
            if is_cachevault and b.pack_energy:
                energy_str = b.pack_energy
                if b.design_capacity:
                    energy_str += f" / {b.design_capacity}"
                bbu_extra += f'<div class="col-auto"><small class="text-muted">{_("Energy")}:</small> <strong class="small">{energy_str}</strong></div>'
            elif not is_cachevault and b.capacitance:
                bbu_extra += f'<div class="col-auto"><small class="text-muted">{_("Capacitance")}:</small> <strong class="small">{b.capacitance}</strong></div>'
            if b.flash_size:
                bbu_extra += f'<div class="col-auto"><small class="text-muted">{_("Flash")}:</small> <strong class="small">{b.flash_size}</strong></div>'
            if b.manufacture_date:
                bbu_extra += f'<div class="col-auto"><small class="text-muted">{_("Mfg Date")}:</small> <strong class="small">{b.manufacture_date}</strong></div>'
            if b.replacement_needed:
                bbu_extra += f'<div class="col-auto"><span class="badge bg-danger">{_("Replacement Required")}</span></div>'
            bbu_html = f'''
            <div class="card bg-light border mt-3"><div class="card-body p-3">
              <h6 class="card-title small fw-bold mb-2">BBU / CacheVault</h6>
              <div class="row g-2">
                <div class="col-auto"><small class="text-muted">{_("Status")}:</small> <span class="badge {bbu_status_badge}">{b.state or "N/A"}</span></div>
                <div class="col-auto"><small class="text-muted">{_("Type")}:</small> <strong class="small">{b.bbu_type or "N/A"}</strong></div>
                <div class="col-auto"><small class="text-muted">{_("Temp")}:</small> <strong class="small">{b.temperature or "N/A"} C</strong></div>
                <div class="col-auto"><small class="text-muted">{_("Charge")}:</small> <strong class="small">{charge_display}</strong></div>
                {bbu_extra}
              </div>
            </div></div>'''

        unc_cls = ' text-danger' if (ctrl.memory_uncorrectable_errors or 0) > 0 else ''
        ecc_cls = ' text-warning' if (ctrl.ecc_bucket_count or 0) > 0 else ''
        raid_levels = ", ".join(ctrl.supported_raid_levels) if ctrl.supported_raid_levels else "N/A"
        driver_str = f"{ctrl.driver_name or ''} {ctrl.driver_version or ''}".strip() or "N/A"

        # Scheduled tasks section
        sched_parts = []
        if ctrl.next_cc_launch:
            sched_parts.append(f'<div class="col-auto"><small class="text-muted">{_("Next CC")}:</small> <strong class="small">{ctrl.next_cc_launch}</strong></div>')
        if ctrl.next_pr_launch:
            sched_parts.append(f'<div class="col-auto"><small class="text-muted">{_("Next PR")}:</small> <strong class="small">{ctrl.next_pr_launch}</strong></div>')
        if ctrl.next_battery_learn:
            sched_parts.append(f'<div class="col-auto"><small class="text-muted">{_("Next Battery Learn")}:</small> <strong class="small">{ctrl.next_battery_learn}</strong></div>')
        sched_html = ""
        if sched_parts:
            sched_html = f'''<div class="card bg-light border mt-3"><div class="card-body p-3">
              <h6 class="card-title small fw-bold mb-2">{_("Scheduled Tasks")}</h6>
              <div class="row g-2">{"".join(sched_parts)}</div>
            </div></div>'''

        html_parts.append(f'''
        <div class="card border-0 shadow-sm mb-3">
          <div class="card-header bg-white d-flex justify-content-between align-items-center">
            <h6 class="mb-0">{ctrl.model or "Controller"} #{ctrl.controller_id}</h6>
            <span class="badge {status_badge}">{ctrl.status or "N/A"}</span>
          </div>
          <div class="card-body">
            <div class="row g-3">
              <div class="col-md-6">
                <table class="table table-sm table-borderless mb-0">
                  <tr><td class="text-muted">{_("Serial")}:</td><td class="fw-semibold">{ctrl.serial_number or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("Firmware")}:</td><td class="fw-semibold">{ctrl.firmware_version or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("BIOS")}:</td><td class="fw-semibold small">{ctrl.bios_version or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("Driver")}:</td><td class="fw-semibold">{driver_str}</td></tr>
                  <tr><td class="text-muted">{_("FW Package")}:</td><td class="fw-semibold">{ctrl.firmware_package_build or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("Interface")}:</td><td class="fw-semibold">{ctrl.host_interface or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("RAID Levels")}:</td><td class="fw-semibold small">{raid_levels}</td></tr>
                </table>
              </div>
              <div class="col-md-6">
                <div class="mb-3">
                  <div class="d-flex justify-content-between align-items-center mb-1">
                    <small class="text-muted fw-semibold">{_("Temperature")}</small>
                    <span class="badge {temp_badge}">{temp} C</span>
                  </div>
                  <div class="progress" style="height: 8px;">
                    <div class="progress-bar {temp_bar}" style="width: {min(temp, 100)}%"></div>
                  </div>
                </div>
                <table class="table table-sm table-borderless mb-0">
                  <tr><td class="text-muted">{_("Memory")}:</td><td class="fw-semibold">{ctrl.memory_size or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("Correctable Errors")}:</td><td class="fw-semibold">{ctrl.memory_correctable_errors or 0}</td></tr>
                  <tr><td class="text-muted">{_("Uncorrectable Errors")}:</td><td class="fw-semibold{unc_cls}">{ctrl.memory_uncorrectable_errors or 0}</td></tr>
                  <tr><td class="text-muted">{_("ECC Bucket Count")}:</td><td class="fw-semibold{ecc_cls}">{ctrl.ecc_bucket_count or 0}</td></tr>
                  <tr><td class="text-muted">{_("Rebuild Rate")}:</td><td class="fw-semibold">{ctrl.rebuild_rate or "N/A"}%</td></tr>
                  <tr><td class="text-muted">{_("Patrol Read")}:</td><td class="fw-semibold">{ctrl.patrol_read_status or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("CC Status")}:</td><td class="fw-semibold">{ctrl.cc_status or "N/A"}</td></tr>
                  <tr><td class="text-muted">{_("Alarm")}:</td><td class="fw-semibold">{ctrl.alarm_status or "N/A"}</td></tr>
                </table>
              </div>
            </div>
            {sched_html}
            {bbu_html}
          </div>
        </div>''')

    return HTMLResponse(content="\n".join(html_parts))


@router.get(
    "/servers/{server_id}/virtual-drives",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_vd_partial(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return virtual drives HTML partial for HTMX tab loading."""
    from app.database import async_session
    from app.models.controller import Controller
    from app.models.virtual_drive import VirtualDrive

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(
            select(VirtualDrive)
            .join(Controller, VirtualDrive.controller_id == Controller.id)
            .where(Controller.server_id == server_id)
            .order_by(VirtualDrive.dg_id, VirtualDrive.vd_id)
        )
        vds = result.scalars().all()

    if not vds:
        return HTMLResponse(
            f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No virtual drives found for this server.")}</p></div>'
        )

    rows = []
    for vd in vds:
        state_cls = {
            "optl": "bg-success", "optimal": "bg-success",
            "dgrd": "bg-warning text-dark", "degraded": "bg-warning text-dark",
            "pdgd": "bg-danger", "ofln": "bg-danger",
            "rec": "bg-info text-dark",
        }.get((vd.state or "").lower(), "bg-secondary")
        active_ops = vd.active_operations or ""
        ops_html = (f'<span class="badge bg-info text-dark">{active_ops}</span>'
                    if active_ops and active_ops.lower() != "none"
                    else '<span class="text-muted small">None</span>')
        rows.append(f'''<tr>
          <td class="fw-semibold">{vd.dg_id or ""}/{vd.vd_id}</td>
          <td>{vd.name or ""}</td><td>{vd.raid_type or ""}</td>
          <td><span class="badge {state_cls}">{vd.state or "N/A"}</span></td>
          <td class="text-nowrap">{vd.size or "N/A"}</td>
          <td>{vd.cache_policy or "N/A"}</td>
          <td>{vd.write_cache or "N/A"}</td>
          <td>{vd.number_of_drives or 0}</td>
          <td>{vd.span_depth or ""}</td>
          <td>{ops_html}</td>
        </tr>''')

    html = f'''<div class="card border-0 shadow-sm"><div class="card-body p-0">
    <div class="table-responsive"><table class="table table-hover table-sm align-middle mb-0">
    <thead class="table-light"><tr>
      <th>VD#</th><th>{_("Name")}</th><th>RAID</th><th>{_("State")}</th>
      <th>{_("Size")}</th><th>{_("Cache")}</th><th>{_("Write Cache")}</th><th>{_("Drives")}</th>
      <th>{_("Spans")}</th><th>{_("Active Ops")}</th>
    </tr></thead><tbody>{"".join(rows)}</tbody></table></div></div></div>'''
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/physical-drives",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_pd_partial(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return physical drives HTML partial for HTMX tab loading."""
    from app.database import async_session
    from app.models.server import Server
    from app.models.controller import Controller
    from app.models.physical_drive import PhysicalDrive

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(
            select(PhysicalDrive)
            .join(Controller, PhysicalDrive.controller_id == Controller.id)
            .where(Controller.server_id == server_id)
            .order_by(PhysicalDrive.enclosure_id, PhysicalDrive.slot_number)
        )
        pds = result.scalars().all()

        # Always load server for smartctl drives
        srv_result = await db.execute(select(Server).where(Server.id == server_id))
        srv = srv_result.scalar_one_or_none()

    smart_drives = []
    if srv and srv.last_report:
        smart_drives = srv.last_report.get("smart_drives") or []

    # When MegaRAID controllers exist, filter out controller-related drives
    # from the smartctl list (they're already shown in the MegaRAID section)
    if pds and smart_drives:
        _RAID_CTRL_KEYWORDS = ("avago", "lsi", "megaraid", "perc", "broadcom")
        filtered = []
        for d in smart_drives:
            scan_t = (d.get("scan_type") or "").lower()
            model_l = (d.get("model") or "").lower()
            # Skip drives accessed via megaraid passthrough (/dev/bus/N -d megaraid,X)
            if "megaraid" in scan_t:
                continue
            # Skip RAID controller virtual disk devices (e.g. AVAGO MR9361-8i)
            if any(kw in model_l for kw in _RAID_CTRL_KEYWORDS):
                continue
            filtered.append(d)
        smart_drives = filtered

    if not pds and not smart_drives:
        return HTMLResponse(
            f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No physical drives found for this server.")}</p></div>'
        )

    html_parts = []

    # --- Section 1: Hardware RAID physical drives (MegaRAID) ---
    if pds:
        rows = []
        for pd in pds:
            state_cls = {
                "onln": "bg-success", "online": "bg-success",
                "offln": "bg-danger", "ubad": "bg-danger",
                "rbld": "bg-info text-dark",
                "ghs": "bg-cyan", "dhs": "bg-cyan",
            }.get((pd.state or "").lower(), "bg-secondary")
            temp_cls = "text-danger fw-bold" if (pd.temperature or 0) > 50 else ("text-warning" if (pd.temperature or 0) > 40 else "")
            med_cls = " text-danger fw-bold" if (pd.media_error_count or 0) > 0 else ""
            oth_cls = " text-warning fw-bold" if (pd.other_error_count or 0) > 0 else ""
            pf_cls = " text-danger fw-bold" if (pd.predictive_failure or 0) > 0 else ""
            smart_icon = ('<span class="text-danger"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">'
                          '<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566z'
                          'M8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg></span>'
                          if pd.smart_alert else
                          '<span class="text-success"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">'
                          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg></span>')
            temp_str = f"{pd.temperature} C" if pd.temperature is not None else "N/A"
            tooltip_parts = []
            if pd.wwn:
                tooltip_parts.append(f"WWN: {pd.wwn}")
            if pd.serial_number:
                tooltip_parts.append(f"S/N: {pd.serial_number}")
            if pd.firmware_version:
                tooltip_parts.append(f"FW: {pd.firmware_version}")
            if pd.physical_sector_size:
                tooltip_parts.append(f"Phys Sector: {pd.physical_sector_size}")
            row_title = "  ".join(tooltip_parts)
            speed_tooltip = f'{_("Link")}: {pd.link_speed or "N/A"} / {_("Device")}: {pd.device_speed or "N/A"}'
            rows.append(f'''<tr title="{row_title}" data-bs-toggle="tooltip" data-bs-placement="top"
                  style="cursor: pointer;"
                  hx-get="/servers/{server_id}/physical-drives/{pd.enclosure_id}:{pd.slot_number}/smart"
                  hx-target="#smart-modal-body" hx-swap="innerHTML"
                  data-bs-target="#smartModal">
              <td class="fw-semibold">{pd.enclosure_id}:{pd.slot_number}</td>
              <td><span class="badge {state_cls}">{pd.state or "N/A"}</span></td>
              <td>{pd.drive_group if pd.drive_group is not None else ""}</td>
              <td class="text-nowrap">{pd.size or "N/A"}</td>
              <td class="small">{pd.model or "N/A"}</td>
              <td>{pd.media_type or "N/A"}</td><td>{pd.interface_type or "N/A"}</td>
              <td class="small text-nowrap" title="{speed_tooltip}">{pd.link_speed or ""}</td>
              <td><span class="{temp_cls}">{temp_str}</span></td>
              <td class="{med_cls}">{pd.media_error_count or 0}</td>
              <td class="{oth_cls}">{pd.other_error_count or 0}</td>
              <td class="{pf_cls}">{pd.predictive_failure or 0}</td>
              <td>{smart_icon}</td>
            </tr>''')

        section_title = f'<h6 class="fw-bold mb-2">MegaRAID {_("Physical Drives")}</h6>' if smart_drives else ''
        html_parts.append(f'''{section_title}<div class="card border-0 shadow-sm"><div class="card-body p-0">
        <div class="table-responsive"><table class="table table-hover table-sm align-middle mb-0">
        <thead class="table-light"><tr>
          <th>EID:Slot</th><th>{_("State")}</th><th>DG</th><th>{_("Size")}</th>
          <th>{_("Model")}</th><th>{_("Type")}</th><th>{_("Interface")}</th><th>{_("Speed")}</th>
          <th>{_("Temp")}</th><th title="{_("Media Errors")}">Med Err</th>
          <th title="{_("Other Errors")}">Oth Err</th><th title="{_("Predictive Failure")}">Pred.Fail</th><th>SMART</th>
        </tr></thead><tbody>{"".join(rows)}</tbody></table></div></div></div>''')

    # --- Section 2: SMART drives from smartctl ---
    if smart_drives:
        import urllib.parse
        rows = []
        for d in smart_drives:
            device = d.get("device") or "N/A"
            model = d.get("model") or "N/A"
            serial = d.get("serial_number") or ""
            firmware = d.get("firmware_version") or ""
            dev_type = d.get("device_type") or ""
            capacity = d.get("capacity") or "N/A"
            temperature = d.get("temperature")
            power_on = d.get("power_on_hours")
            reallocated = d.get("reallocated_sectors")
            pending = d.get("pending_sectors")
            uncorrectable = d.get("uncorrectable_sectors")
            smart_ok = d.get("smart_status")

            smart_cls = "bg-success" if smart_ok else ("bg-danger" if smart_ok is False else "bg-secondary")
            smart_txt = "PASSED" if smart_ok else ("FAILED" if smart_ok is False else "N/A")
            temp_cls = "text-danger fw-bold" if (temperature or 0) > 50 else ("text-warning" if (temperature or 0) > 40 else "")
            temp_str = f"{temperature} C" if temperature is not None else "N/A"
            realloc_cls = " text-danger fw-bold" if (reallocated or 0) > 0 else ""
            pending_cls = " text-warning fw-bold" if (pending or 0) > 0 else ""
            uncorr_cls = " text-danger fw-bold" if (uncorrectable or 0) > 0 else ""
            poh_str = f"{power_on:,}h" if power_on is not None else "N/A"
            safe_device = urllib.parse.quote(device, safe="")

            rows.append(f'''<tr style="cursor: pointer;"
                  hx-get="/servers/{server_id}/smart-drive/{safe_device}"
                  hx-target="#smart-modal-body" hx-swap="innerHTML"
                  data-bs-toggle="modal" data-bs-target="#smartModal"
                  title="S/N: {serial}  FW: {firmware}">
              <td class="fw-semibold">{device}</td>
              <td>{dev_type}</td>
              <td class="text-nowrap">{capacity}</td>
              <td class="small">{model}</td>
              <td><span class="badge {smart_cls}">{smart_txt}</span></td>
              <td><span class="{temp_cls}">{temp_str}</span></td>
              <td>{poh_str}</td>
              <td class="{realloc_cls}">{reallocated if reallocated is not None else "N/A"}</td>
              <td class="{pending_cls}">{pending if pending is not None else "N/A"}</td>
              <td class="{uncorr_cls}">{uncorrectable if uncorrectable is not None else "N/A"}</td>
            </tr>''')

        section_title = f'<h6 class="fw-bold mb-2 {"mt-4" if pds else ""}">SMART {_("Drives")} (smartctl)</h6>' if pds else ''
        html_parts.append(f'''{section_title}<div class="card border-0 shadow-sm"><div class="card-body p-0">
        <div class="table-responsive"><table class="table table-hover table-sm align-middle mb-0">
        <thead class="table-light"><tr>
          <th>{_("Device")}</th><th>{_("Type")}</th><th>{_("Size")}</th>
          <th>{_("Model")}</th><th>SMART</th><th>{_("Temp")}</th>
          <th title="{_("Power On Hours")}">POH</th>
          <th title="{_("Reallocated Sectors")}">Realloc</th>
          <th title="{_("Pending Sectors")}">Pending</th>
          <th title="{_("Uncorrectable Sectors")}">Uncorr</th>
        </tr></thead><tbody>{"".join(rows)}</tbody></table></div></div></div>''')

    return HTMLResponse(content="".join(html_parts))


@router.get(
    "/servers/{server_id}/events",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_events_partial(
    request: Request,
    server_id: str,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    current_user: dict = Depends(_require_auth),
):
    """Return events HTML partial for HTMX tab loading."""
    from app.models.controller import Controller
    from app.models.event import ControllerEvent
    from sqlalchemy import func, desc

    lang = _get_lang(request)
    _ = _make_gettext(lang)
    per_page = 50

    try:
        from app.database import async_session
        async with async_session() as db:
            # Base query: events for all controllers of this server
            base_q = (
                select(ControllerEvent)
                .join(Controller, ControllerEvent.controller_id == Controller.id)
                .where(Controller.server_id == server_id)
            )
            count_q = (
                select(func.count(ControllerEvent.id))
                .join(Controller, ControllerEvent.controller_id == Controller.id)
                .where(Controller.server_id == server_id)
            )

            if severity and severity.lower() != "all":
                base_q = base_q.where(ControllerEvent.severity == severity.lower())
                count_q = count_q.where(ControllerEvent.severity == severity.lower())

            total = (await db.execute(count_q)).scalar() or 0
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages

            result = await db.execute(
                base_q
                .order_by(desc(ControllerEvent.event_time), desc(ControllerEvent.id))
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
            events = result.scalars().all()
    except Exception as exc:
        logger.error("Failed to load events for server %s: %s", server_id, exc)
        return HTMLResponse(
            content=f'<div class="alert alert-danger">{_("Error loading events")}: {exc}</div>'
        )

    # Severity filter buttons (always shown when events exist for the server)
    sev_options = [
        ("all", _("All"), "btn-outline-secondary"),
        ("info", _("Info"), "btn-outline-info"),
        ("warning", _("Warning"), "btn-outline-warning"),
        ("critical", _("Critical"), "btn-outline-danger"),
        ("progress", _("Progress"), "btn-outline-primary"),
    ]
    active_sev = (severity or "all").lower()
    filter_html = '<div class="mb-3 d-flex gap-1 flex-wrap">'
    for sev_val, sev_label, sev_cls in sev_options:
        is_active = "active" if sev_val == active_sev else ""
        filter_html += (
            f'<button class="btn btn-sm {sev_cls} {is_active}" '
            f'hx-get="/servers/{server_id}/events?severity={sev_val}&page=1" '
            f'hx-target="#events-pane" hx-swap="innerHTML">'
            f'{sev_label}</button>'
        )
    filter_html += '</div>'

    if not events and total == 0:
        # If filtering by severity and no results — show filter + empty message
        if severity and severity.lower() != "all":
            return HTMLResponse(
                content=filter_html
                + f'<div class="text-center py-5 text-muted">'
                f'<p>{_("No events found for this filter.")}</p></div>'
            )
        return HTMLResponse(
            content=f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No events found for this server.")}</p></div>'
        )

    # Table rows
    rows = []
    for evt in events:
        sev = (evt.severity or "info").lower()
        sev_badge = {
            "critical": "bg-danger",
            "fatal": "bg-danger",
            "warning": "bg-warning text-dark",
            "info": "bg-info text-dark",
            "progress": "bg-primary",
        }.get(sev, "bg-secondary")

        time_str = ""
        if evt.event_time:
            time_str = evt.event_time.strftime("%Y-%m-%d %H:%M:%S")

        desc = evt.event_description or ""

        rows.append(
            f'<tr>'
            f'<td class="text-nowrap small">{time_str}</td>'
            f'<td><span class="badge {sev_badge}">{sev}</span></td>'
            f'<td class="small">{evt.event_class or ""}</td>'
            f'<td class="small">{desc}</td>'
            f'</tr>'
        )

    table_html = f'''
    <div class="table-responsive">
    <table class="table table-sm table-hover mb-0">
    <thead class="table-light">
    <tr>
      <th>{_("Time")}</th>
      <th>{_("Severity")}</th>
      <th>{_("Class")}</th>
      <th>{_("Description")}</th>
    </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
    </table>
    </div>'''

    # Pagination
    pag_html = ""
    if total_pages > 1:
        pag_html = '<nav class="mt-3"><ul class="pagination pagination-sm justify-content-center">'
        sev_param = f"&severity={active_sev}" if active_sev != "all" else ""
        if page > 1:
            pag_html += (
                f'<li class="page-item"><a class="page-link" '
                f'hx-get="/servers/{server_id}/events?page={page - 1}{sev_param}" '
                f'hx-target="#events-pane" hx-swap="innerHTML">&laquo;</a></li>'
            )
        # Show page range
        start_p = max(1, page - 3)
        end_p = min(total_pages, page + 3)
        for p in range(start_p, end_p + 1):
            active_cls = "active" if p == page else ""
            pag_html += (
                f'<li class="page-item {active_cls}"><a class="page-link" '
                f'hx-get="/servers/{server_id}/events?page={p}{sev_param}" '
                f'hx-target="#events-pane" hx-swap="innerHTML">{p}</a></li>'
            )
        if page < total_pages:
            pag_html += (
                f'<li class="page-item"><a class="page-link" '
                f'hx-get="/servers/{server_id}/events?page={page + 1}{sev_param}" '
                f'hx-target="#events-pane" hx-swap="innerHTML">&raquo;</a></li>'
            )
        pag_html += '</ul></nav>'

    info_html = f'<div class="text-muted small mb-2">{_("Total")}: {total} | {_("Page")} {page}/{total_pages}</div>'

    html = f'<div class="p-3">{filter_html}{info_html}{table_html}{pag_html}</div>'
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/agent",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_agent_partial(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return agent info HTML partial for HTMX tab loading."""
    from app.database import async_session
    from app.models.server import Server

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(select(Server).where(Server.id == server_id))
        srv = result.scalar_one_or_none()

    if not srv:
        return HTMLResponse(f'<div class="alert alert-danger">Server not found</div>')

    last_seen_display = srv.last_seen.strftime("%d.%m.%Y %H:%M") if srv.last_seen else "N/A"
    registered_display = srv.created_at.strftime("%d.%m.%Y %H:%M") if srv.created_at else "N/A"
    debug_checked = "checked" if srv.debug_mode else ""

    html = f"""
    <div class="card border-0 shadow-sm">
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <table class="table table-sm table-borderless mb-0">
              <tr><td class="text-muted">{_("Agent Version")}:</td><td class="fw-semibold">{srv.agent_version or "N/A"}</td></tr>
              <tr><td class="text-muted">{_("StorCLI Version")}:</td><td class="fw-semibold">{srv.storcli_version or "N/A"}</td></tr>
              <tr><td class="text-muted">{_("Last Seen")}:</td><td class="fw-semibold">{last_seen_display}</td></tr>
              <tr><td class="text-muted">{_("Registered")}:</td><td class="fw-semibold">{registered_display}</td></tr>
            </table>
          </div>
          <div class="col-md-6">
            <div class="mb-3">
              <label class="form-label fw-semibold">{_("Debug Logging")}</label>
              <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="debugToggle" {debug_checked}
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
    "/servers/{server_id}/software-raids",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_software_raids_partial(
    request: Request,
    server_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return software RAID HTML partial for HTMX tab loading."""
    from app.database import async_session
    from app.models.software_raid import SoftwareRaid

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    async with async_session() as db:
        result = await db.execute(
            select(SoftwareRaid)
            .where(SoftwareRaid.server_id == server_id)
            .order_by(SoftwareRaid.array_name)
        )
        raids = result.scalars().all()

    if not raids:
        return HTMLResponse(
            f'<div class="text-center py-5 text-muted">'
            f'<p>{_("No software RAID arrays found for this server.")}</p></div>'
        )

    rows = []
    for sr in raids:
        state_lower = (sr.state or "").lower()
        if state_lower in ("active", "clean"):
            state_cls = "bg-success"
        elif state_lower in ("degraded", "inactive"):
            state_cls = "bg-danger"
        elif state_lower in ("rebuilding", "recovering", "resyncing"):
            state_cls = "bg-warning text-dark"
        else:
            state_cls = "bg-secondary"

        # Member devices display
        members_html = ""
        if sr.member_devices:
            mem_parts = []
            for m in sr.member_devices:
                dev = m.get("device", "?")
                mstate = (m.get("state") or "").lower()
                if mstate == "faulty":
                    mem_parts.append(f'<span class="badge bg-danger me-1">{dev}</span>')
                elif mstate == "spare":
                    mem_parts.append(f'<span class="badge bg-info text-dark me-1">{dev}</span>')
                else:
                    mem_parts.append(f'<span class="badge bg-success me-1">{dev}</span>')
            members_html = " ".join(mem_parts)

        # Rebuild progress bar
        rebuild_html = ""
        if sr.rebuild_progress is not None:
            pct = min(sr.rebuild_progress, 100)
            rebuild_html = (
                f'<div class="progress" style="height: 16px; min-width: 80px;">'
                f'<div class="progress-bar bg-info" style="width: {pct:.1f}%">{pct:.1f}%</div></div>'
            )
        else:
            rebuild_html = '<span class="text-muted">—</span>'

        failed_cls = " text-danger fw-bold" if (sr.failed_devices or 0) > 0 else ""

        rows.append(f'''<tr>
          <td class="fw-semibold">{sr.array_name}</td>
          <td>{sr.raid_level or "N/A"}</td>
          <td><span class="badge {state_cls}">{sr.state or "N/A"}</span></td>
          <td class="text-nowrap">{sr.array_size or "N/A"}</td>
          <td>{sr.active_devices if sr.active_devices is not None else "?"}/{sr.num_devices if sr.num_devices is not None else "?"}</td>
          <td class="{failed_cls}">{sr.failed_devices or 0}</td>
          <td>{sr.spare_devices or 0}</td>
          <td>{rebuild_html}</td>
          <td>{members_html}</td>
        </tr>''')

    html = f'''<div class="card border-0 shadow-sm"><div class="card-body p-0">
    <div class="table-responsive"><table class="table table-hover table-sm align-middle mb-0">
    <thead class="table-light"><tr>
      <th>{_("Array")}</th><th>{_("Level")}</th><th>{_("State")}</th><th>{_("Size")}</th>
      <th>{_("Drives")}</th><th>{_("Failed")}</th><th>{_("Spare")}</th>
      <th>{_("Rebuild Progress")}</th><th>{_("Members")}</th>
    </tr></thead><tbody>{"".join(rows)}</tbody></table></div></div></div>'''
    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/smart-drive/{device_path:path}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_smart_drive_modal(
    request: Request,
    server_id: str,
    device_path: str,
    current_user: dict = Depends(_require_auth),
):
    """Return SMART data modal for a smartctl-detected drive (no hardware RAID)."""
    import urllib.parse
    from app.database import async_session
    from app.models.server import Server

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    device_path = urllib.parse.unquote(device_path)

    async with async_session() as db:
        result = await db.execute(select(Server).where(Server.id == server_id))
        srv = result.scalar_one_or_none()

    if not srv or not srv.last_report:
        return HTMLResponse(f'<div class="alert alert-warning">{_("No SMART data available")}</div>')

    smart_drives = srv.last_report.get("smart_drives") or []
    drive = None
    for d in smart_drives:
        if d.get("device") == device_path:
            drive = d
            break

    if not drive:
        return HTMLResponse(f'<div class="alert alert-warning">{_("Drive not found")}: {device_path}</div>')

    # Drive identity
    model = drive.get("model") or "N/A"
    serial = drive.get("serial_number") or "N/A"
    firmware = drive.get("firmware_version") or "N/A"
    dev_type = drive.get("device_type") or "N/A"
    capacity = drive.get("capacity") or "N/A"

    # SMART status
    smart_ok = drive.get("smart_status")
    smart_cls = "bg-success" if smart_ok else ("bg-danger" if smart_ok is False else "bg-secondary")
    smart_txt = "PASSED" if smart_ok else ("FAILED" if smart_ok is False else "N/A")

    # Key metrics
    temperature = drive.get("temperature")
    power_on = drive.get("power_on_hours")
    reallocated = drive.get("reallocated_sectors")
    pending = drive.get("pending_sectors")
    uncorrectable = drive.get("uncorrectable_sectors")
    temp_str = f"{temperature} C" if temperature is not None else "N/A"
    poh_str = f"{power_on:,}" if power_on is not None else "N/A"

    html = f'''
    <div class="mb-3">
      <h6 class="fw-bold">{device_path}</h6>
      <table class="table table-sm table-borderless mb-2">
        <tr><td class="text-muted" style="width:40%">{_("Model")}:</td><td class="fw-semibold">{model}</td></tr>
        <tr><td class="text-muted">{_("Serial")}:</td><td class="fw-semibold">{serial}</td></tr>
        <tr><td class="text-muted">{_("Firmware")}:</td><td class="fw-semibold">{firmware}</td></tr>
        <tr><td class="text-muted">{_("Type")}:</td><td class="fw-semibold">{dev_type}</td></tr>
        <tr><td class="text-muted">{_("Capacity")}:</td><td class="fw-semibold">{capacity}</td></tr>
        <tr><td class="text-muted">SMART {_("Status")}:</td><td><span class="badge {smart_cls}">{smart_txt}</span></td></tr>
        <tr><td class="text-muted">{_("Temperature")}:</td><td class="fw-semibold">{temp_str}</td></tr>
        <tr><td class="text-muted">{_("Power On Hours")}:</td><td class="fw-semibold">{poh_str}</td></tr>
        <tr><td class="text-muted">{_("Reallocated Sectors")}:</td><td class="fw-semibold {"text-danger" if (reallocated or 0) > 0 else ""}">{reallocated if reallocated is not None else "N/A"}</td></tr>
        <tr><td class="text-muted">{_("Pending Sectors")}:</td><td class="fw-semibold {"text-warning" if (pending or 0) > 0 else ""}">{pending if pending is not None else "N/A"}</td></tr>
        <tr><td class="text-muted">{_("Uncorrectable Sectors")}:</td><td class="fw-semibold {"text-danger" if (uncorrectable or 0) > 0 else ""}">{uncorrectable if uncorrectable is not None else "N/A"}</td></tr>
      </table>
    </div>'''

    # SMART attributes table (ATA)
    attrs = drive.get("smart_attributes") or []
    if attrs:
        attr_rows = []
        for a in attrs:
            attr_id = a.get("id", "")
            attr_name = a.get("name", "")
            attr_value = a.get("value", "")
            attr_worst = a.get("worst", "")
            attr_thresh = a.get("thresh", "")
            attr_raw = a.get("raw", "")
            attr_flags = a.get("flags", "")
            # Highlight if value <= threshold
            row_cls = ""
            try:
                if int(attr_value) <= int(attr_thresh) and int(attr_thresh) > 0:
                    row_cls = ' class="table-danger"'
            except (ValueError, TypeError):
                pass
            attr_rows.append(f'<tr{row_cls}><td>{attr_id}</td><td class="small">{attr_name}</td>'
                             f'<td>{attr_value}</td><td>{attr_worst}</td><td>{attr_thresh}</td>'
                             f'<td class="small">{attr_flags}</td><td class="fw-semibold">{attr_raw}</td></tr>')
        html += f'''
        <h6 class="fw-bold mt-3">SMART {_("Attributes")}</h6>
        <div class="table-responsive"><table class="table table-sm table-hover mb-0">
        <thead class="table-light"><tr>
          <th>ID</th><th>{_("Attribute")}</th><th>{_("Value")}</th><th>{_("Worst")}</th>
          <th>{_("Threshold")}</th><th>{_("Flags")}</th><th>Raw</th>
        </tr></thead><tbody>{"".join(attr_rows)}</tbody></table></div>'''

    # NVMe health log fallback
    smart_data = drive.get("smart_data") or {}
    nvme_log = smart_data.get("nvme_smart_health_information_log")
    if nvme_log and not attrs:
        nvme_rows = []
        for k, v in nvme_log.items():
            label = k.replace("_", " ").title()
            nvme_rows.append(f'<tr><td class="text-muted small">{label}</td><td class="fw-semibold">{v}</td></tr>')
        html += f'''
        <h6 class="fw-bold mt-3">NVMe Health Log</h6>
        <div class="table-responsive"><table class="table table-sm mb-0">
        <tbody>{"".join(nvme_rows)}</tbody></table></div>'''

    return HTMLResponse(content=html)


@router.get(
    "/servers/{server_id}/physical-drives/{drive_id}/smart",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def server_pd_smart_partial(
    request: Request,
    server_id: str,
    drive_id: str,
    current_user: dict = Depends(_require_auth),
):
    """Return SMART data HTML partial for modal display."""
    from app.database import async_session
    from app.models.controller import Controller
    from app.models.physical_drive import PhysicalDrive

    lang = _get_lang(request)
    _ = _make_gettext(lang)

    # Parse drive_id format: "enclosure_id:slot_number"
    parts = drive_id.split(":")
    if len(parts) != 2:
        return HTMLResponse(
            f'<div class="text-center py-4">'
            f'<p class="text-muted">{_("No SMART data available for this drive.")}</p></div>'
        )

    try:
        eid = int(parts[0])
        slot = int(parts[1])
    except ValueError:
        return HTMLResponse(
            f'<div class="text-center py-4">'
            f'<p class="text-muted">{_("No SMART data available for this drive.")}</p></div>'
        )

    async with async_session() as db:
        result = await db.execute(
            select(PhysicalDrive)
            .join(Controller, PhysicalDrive.controller_id == Controller.id)
            .where(
                Controller.server_id == server_id,
                PhysicalDrive.enclosure_id == eid,
                PhysicalDrive.slot_number == slot,
            )
        )
        pd = result.scalar_one_or_none()

    if not pd or not pd.smart_data:
        return HTMLResponse(
            f'<div class="text-center py-4">'
            f'<h6>{_("SMART Data")} — {drive_id}</h6>'
            f'<p class="text-muted">{_("No SMART data available for this drive.")}</p></div>'
        )

    smart = pd.smart_data or {}

    # Drive identity
    model = pd.model or smart.get("model_name", "N/A")
    serial = pd.serial_number or smart.get("serial_number", "N/A")
    firmware = pd.firmware_version or smart.get("firmware_version", "N/A")

    # SMART status
    smart_status_obj = smart.get("smart_status", {})
    passed = smart_status_obj.get("passed")
    if passed is True:
        status_badge = f'<span class="badge bg-success">{_("PASSED")}</span>'
    elif passed is False:
        status_badge = f'<span class="badge bg-danger">{_("FAILED")}</span>'
    else:
        status_badge = '<span class="badge bg-secondary">N/A</span>'

    # Temperature
    temp = pd.temperature
    if temp is None:
        temp_obj = smart.get("temperature", {})
        if isinstance(temp_obj, dict):
            temp = temp_obj.get("current")
    temp_str = f"{temp} °C" if temp is not None else "N/A"

    # Power-on hours
    poh_obj = smart.get("power_on_time", {})
    poh = poh_obj.get("hours") if isinstance(poh_obj, dict) else None
    poh_str = f"{poh:,}" if poh is not None else "N/A"

    # Key metrics from SMART attributes
    realloc = smart.get("reallocated_sectors")
    if realloc is None:
        realloc = pd.smart_data.get("reallocated_sectors") if pd.smart_data else None
    realloc_str = str(realloc) if realloc is not None else "N/A"

    # Metrics header cards
    header_html = f'''
    <div class="mb-3">
      <h6>{_("SMART Data")} — {drive_id}</h6>
      <div class="row g-2 mb-2">
        <div class="col-auto"><small class="text-muted">{_("Model")}:</small> <strong>{model}</strong></div>
        <div class="col-auto"><small class="text-muted">{_("Serial Number")}:</small> <strong>{serial}</strong></div>
        <div class="col-auto"><small class="text-muted">{_("Firmware")}:</small> <strong>{firmware}</strong></div>
      </div>
      <div class="row g-3 mb-3">
        <div class="col-auto"><small class="text-muted">{_("SMART Status")}:</small> {status_badge}</div>
        <div class="col-auto"><small class="text-muted">{_("Temperature")}:</small> <strong>{temp_str}</strong></div>
        <div class="col-auto"><small class="text-muted">{_("Power-On Hours")}:</small> <strong>{poh_str}</strong></div>
        <div class="col-auto"><small class="text-muted">{_("Reallocated Sectors")}:</small> <strong>{realloc_str}</strong></div>
      </div>
    </div>'''

    # SMART attributes table
    ata_attrs = smart.get("ata_smart_attributes", {}).get("table", [])
    if ata_attrs:
        attr_rows = []
        for attr in ata_attrs:
            attr_id = attr.get("id", "")
            name = attr.get("name", "")
            value = attr.get("value", "")
            worst = attr.get("worst", "")
            thresh = attr.get("thresh", 0)
            raw_obj = attr.get("raw", {})
            raw_str = raw_obj.get("string", str(raw_obj.get("value", ""))) if isinstance(raw_obj, dict) else str(raw_obj)
            type_obj = attr.get("type", {})
            type_str = type_obj.get("string", "") if isinstance(type_obj, dict) else str(type_obj)
            wf_obj = attr.get("when_failed", {})
            wf_str = wf_obj.get("string", "") if isinstance(wf_obj, dict) else str(wf_obj or "")

            row_cls = ""
            if thresh and value and isinstance(value, (int, float)) and isinstance(thresh, (int, float)):
                if value <= thresh:
                    row_cls = ' class="table-danger"'

            attr_rows.append(
                f'<tr{row_cls}><td>{attr_id}</td><td>{name}</td><td>{value}</td>'
                f'<td>{worst}</td><td>{thresh}</td><td class="small">{type_str}</td>'
                f'<td class="small">{wf_str}</td><td class="small text-nowrap">{raw_str}</td></tr>'
            )

        attrs_html = f'''
        <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
          <table class="table table-sm table-hover align-middle mb-0">
            <thead class="table-light sticky-top">
              <tr>
                <th>ID</th><th>{_("Attribute")}</th><th>{_("Value")}</th>
                <th>{_("Worst")}</th><th>{_("Threshold")}</th><th>{_("Type")}</th>
                <th>When Failed</th><th>{_("Raw Value")}</th>
              </tr>
            </thead>
            <tbody>{"".join(attr_rows)}</tbody>
          </table>
        </div>'''
    else:
        # NVMe health log
        nvme_log = smart.get("nvme_smart_health_information_log", {})
        if nvme_log:
            nvme_rows = []
            for key, val in nvme_log.items():
                label = key.replace("_", " ").title()
                nvme_rows.append(f'<tr><td>{label}</td><td class="fw-semibold">{val}</td></tr>')
            attrs_html = f'''
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
              <table class="table table-sm table-hover align-middle mb-0">
                <thead class="table-light sticky-top">
                  <tr><th>{_("Attribute")}</th><th>{_("Value")}</th></tr>
                </thead>
                <tbody>{"".join(nvme_rows)}</tbody>
              </table>
            </div>'''
        else:
            attrs_html = f'<p class="text-muted text-center">{_("No SMART data available for this drive.")}</p>'

    html = header_html + attrs_html
    return HTMLResponse(content=html)
