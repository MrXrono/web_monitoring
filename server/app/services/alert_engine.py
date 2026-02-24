"""
Alert evaluation engine.

Evaluates all enabled alert rules against a server's current state,
creates AlertHistory entries for new alerts, respects cooldown periods,
resolves cleared conditions, and triggers Telegram notifications.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, and_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Server,
    Controller,
    BbuUnit,
    VirtualDrive,
    PhysicalDrive,
    AlertRule,
    AlertHistory,
)
from app.services import telegram_notifier

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in rule definitions (28 total)
# ---------------------------------------------------------------------------

BUILTIN_RULES: list[dict[str, Any]] = [
    # ---- Virtual Drive rules (6) ----
    {
        "name": "VD Degraded",
        "name_ru": "VD деградирован",
        "description": "Virtual drive is in Degraded state",
        "description_ru": "Виртуальный диск в состоянии Degraded",
        "category": "virtual_drive",
        "condition_type": "vd_state",
        "condition_params": {"states": ["degraded", "dgrd"]},
        "severity": "critical",
        "cooldown_minutes": 30,
    },
    {
        "name": "VD Partially Degraded",
        "name_ru": "VD частично деградирован",
        "description": "Virtual drive is in Partially Degraded state",
        "description_ru": "Виртуальный диск частично деградирован",
        "category": "virtual_drive",
        "condition_type": "vd_state",
        "condition_params": {"states": ["partially_degraded", "pdgd"]},
        "severity": "critical",
        "cooldown_minutes": 30,
    },
    {
        "name": "VD Offline",
        "name_ru": "VD офлайн",
        "description": "Virtual drive is Offline",
        "description_ru": "Виртуальный диск отключен",
        "category": "virtual_drive",
        "condition_type": "vd_state",
        "condition_params": {"states": ["offline", "offln"]},
        "severity": "critical",
        "cooldown_minutes": 15,
    },
    {
        "name": "VD Rebuilding",
        "name_ru": "VD в процессе ребилда",
        "description": "Virtual drive is being rebuilt",
        "description_ru": "Виртуальный диск перестраивается",
        "category": "virtual_drive",
        "condition_type": "vd_state",
        "condition_params": {"states": ["rebuilding", "rbld"]},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "VD Not Optimal",
        "name_ru": "VD не в оптимальном состоянии",
        "description": "Virtual drive is in a non-optimal state (not Optimal/Online)",
        "description_ru": "Виртуальный диск не в оптимальном состоянии",
        "category": "virtual_drive",
        "condition_type": "vd_state_not_in",
        "condition_params": {"healthy_states": ["optimal", "optl"]},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "VD Cache Write-Through",
        "name_ru": "VD кэш в режиме Write-Through",
        "description": "Virtual drive cache policy is Write-Through (performance impact)",
        "description_ru": "Политика кэша виртуального диска - Write-Through (влияние на производительность)",
        "category": "virtual_drive",
        "condition_type": "vd_cache_wt",
        "condition_params": {"cache_patterns": ["wt", "write through", "write-through", "writethrough"]},
        "severity": "info",
        "cooldown_minutes": 1440,
    },

    # ---- Physical Drive rules (11) ----
    {
        "name": "PD Failed",
        "name_ru": "PD отказал",
        "description": "Physical drive has failed",
        "description_ru": "Физический диск отказал",
        "category": "physical_drive",
        "condition_type": "pd_state",
        "condition_params": {"states": ["failed", "ubad", "ubunsp"]},
        "severity": "critical",
        "cooldown_minutes": 15,
    },
    {
        "name": "PD Rebuilding",
        "name_ru": "PD в процессе ребилда",
        "description": "Physical drive is being rebuilt",
        "description_ru": "Физический диск перестраивается",
        "category": "physical_drive",
        "condition_type": "pd_state",
        "condition_params": {"states": ["rebuild", "rbld"]},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "PD Copyback",
        "name_ru": "PD в процессе копирования",
        "description": "Physical drive copyback in progress",
        "description_ru": "Выполняется копирование физического диска",
        "category": "physical_drive",
        "condition_type": "pd_state",
        "condition_params": {"states": ["copyback", "cpybk"]},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "PD Foreign",
        "name_ru": "PD иностранная конфигурация",
        "description": "Physical drive has foreign configuration",
        "description_ru": "Физический диск имеет иностранную конфигурацию",
        "category": "physical_drive",
        "condition_type": "pd_state",
        "condition_params": {"states": ["foreign", "frgn"]},
        "severity": "warning",
        "cooldown_minutes": 1440,
    },
    {
        "name": "PD Media Errors > 0",
        "name_ru": "PD медиа-ошибки > 0",
        "description": "Physical drive has media errors",
        "description_ru": "На физическом диске обнаружены медиа-ошибки",
        "category": "physical_drive",
        "condition_type": "pd_counter_gt",
        "condition_params": {"field": "media_error_count", "threshold": 0},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "PD Media Errors > 10",
        "name_ru": "PD медиа-ошибки > 10",
        "description": "Physical drive has more than 10 media errors",
        "description_ru": "На физическом диске более 10 медиа-ошибок",
        "category": "physical_drive",
        "condition_type": "pd_counter_gt",
        "condition_params": {"field": "media_error_count", "threshold": 10},
        "severity": "critical",
        "cooldown_minutes": 30,
    },
    {
        "name": "PD Predictive Failure",
        "name_ru": "PD предиктивный отказ",
        "description": "Physical drive reports predictive failure",
        "description_ru": "Физический диск сообщает о предиктивном отказе",
        "category": "physical_drive",
        "condition_type": "pd_counter_gt",
        "condition_params": {"field": "predictive_failure", "threshold": 0},
        "severity": "critical",
        "cooldown_minutes": 30,
    },
    {
        "name": "PD SMART Alert",
        "name_ru": "PD SMART тревога",
        "description": "Physical drive has triggered a SMART alert",
        "description_ru": "Физический диск активировал SMART тревогу",
        "category": "physical_drive",
        "condition_type": "pd_smart_alert",
        "condition_params": {},
        "severity": "critical",
        "cooldown_minutes": 30,
    },
    {
        "name": "PD Temperature > 55C",
        "name_ru": "PD температура > 55C",
        "description": "Physical drive temperature exceeds 55 degrees Celsius",
        "description_ru": "Температура физического диска превышает 55 градусов",
        "category": "physical_drive",
        "condition_type": "pd_temp_gt",
        "condition_params": {"threshold": 55},
        "severity": "warning",
        "cooldown_minutes": 30,
    },
    {
        "name": "PD Temperature > 65C",
        "name_ru": "PD температура > 65C",
        "description": "Physical drive temperature exceeds 65 degrees Celsius (critical)",
        "description_ru": "Температура физического диска превышает 65 градусов (критично)",
        "category": "physical_drive",
        "condition_type": "pd_temp_gt",
        "condition_params": {"threshold": 65},
        "severity": "critical",
        "cooldown_minutes": 15,
    },
    {
        "name": "PD Other Errors > 0",
        "name_ru": "PD другие ошибки > 0",
        "description": "Physical drive has other (non-media) errors",
        "description_ru": "На физическом диске обнаружены другие ошибки",
        "category": "physical_drive",
        "condition_type": "pd_counter_gt",
        "condition_params": {"field": "other_error_count", "threshold": 0},
        "severity": "warning",
        "cooldown_minutes": 60,
    },

    # ---- Controller rules (4) ----
    {
        "name": "Controller Not OK",
        "name_ru": "Контроллер не ОК",
        "description": "RAID controller status is not OK/Optimal",
        "description_ru": "Статус RAID контроллера не OK/Optimal",
        "category": "controller",
        "condition_type": "ctrl_status_not_ok",
        "condition_params": {"healthy_states": ["ok", "optimal"]},
        "severity": "critical",
        "cooldown_minutes": 15,
    },
    {
        "name": "Controller ROC Temp > 80C",
        "name_ru": "Контроллер ROC температура > 80C",
        "description": "Controller ROC temperature exceeds 80 degrees Celsius",
        "description_ru": "Температура ROC контроллера превышает 80 градусов",
        "category": "controller",
        "condition_type": "ctrl_roc_temp_gt",
        "condition_params": {"threshold": 80},
        "severity": "warning",
        "cooldown_minutes": 30,
    },
    {
        "name": "Controller ROC Temp > 95C",
        "name_ru": "Контроллер ROC температура > 95C",
        "description": "Controller ROC temperature exceeds 95 degrees Celsius (critical)",
        "description_ru": "Температура ROC контроллера превышает 95 градусов (критично)",
        "category": "controller",
        "condition_type": "ctrl_roc_temp_gt",
        "condition_params": {"threshold": 95},
        "severity": "critical",
        "cooldown_minutes": 15,
    },
    {
        "name": "Controller Memory Errors",
        "name_ru": "Контроллер ошибки памяти",
        "description": "Controller has uncorrectable memory errors",
        "description_ru": "Контроллер имеет неисправимые ошибки памяти",
        "category": "controller",
        "condition_type": "ctrl_memory_errors",
        "condition_params": {"field": "memory_uncorrectable_errors", "threshold": 0},
        "severity": "critical",
        "cooldown_minutes": 60,
    },

    # ---- BBU rules (4) ----
    {
        "name": "BBU Not Optimal",
        "name_ru": "BBU не в оптимальном состоянии",
        "description": "Battery Backup Unit is not in Optimal/Ready state",
        "description_ru": "Батарея контроллера не в оптимальном состоянии",
        "category": "bbu",
        "condition_type": "bbu_state_not_ok",
        "condition_params": {"healthy_states": ["ok", "optimal", "ready"]},
        "severity": "warning",
        "cooldown_minutes": 60,
    },
    {
        "name": "BBU Replacement Needed",
        "name_ru": "BBU требует замены",
        "description": "Battery Backup Unit needs replacement",
        "description_ru": "Батарея контроллера требует замены",
        "category": "bbu",
        "condition_type": "bbu_replacement",
        "condition_params": {},
        "severity": "critical",
        "cooldown_minutes": 1440,
    },
    {
        "name": "BBU Temperature > 50C",
        "name_ru": "BBU температура > 50C",
        "description": "BBU temperature exceeds 50 degrees Celsius",
        "description_ru": "Температура батареи контроллера превышает 50 градусов",
        "category": "bbu",
        "condition_type": "bbu_temp_gt",
        "condition_params": {"threshold": 50},
        "severity": "warning",
        "cooldown_minutes": 30,
    },
    {
        "name": "BBU Learn Cycle Failed",
        "name_ru": "BBU цикл обучения неуспешен",
        "description": "BBU learn cycle has failed",
        "description_ru": "Цикл обучения батареи контроллера завершился с ошибкой",
        "category": "bbu",
        "condition_type": "bbu_learn_failed",
        "condition_params": {"failed_states": ["failed", "error", "fail"]},
        "severity": "warning",
        "cooldown_minutes": 1440,
    },

    # ---- Agent rules (3) ----
    {
        "name": "Agent Offline > 20min",
        "name_ru": "Агент офлайн > 20мин",
        "description": "Agent has not reported for more than 20 minutes",
        "description_ru": "Агент не отправлял отчёт более 20 минут",
        "category": "agent",
        "condition_type": "agent_offline",
        "condition_params": {"minutes": 20},
        "severity": "warning",
        "cooldown_minutes": 20,
    },
    {
        "name": "Agent Offline > 60min",
        "name_ru": "Агент офлайн > 60мин",
        "description": "Agent has not reported for more than 60 minutes",
        "description_ru": "Агент не отправлял отчёт более 60 минут",
        "category": "agent",
        "condition_type": "agent_offline",
        "condition_params": {"minutes": 60},
        "severity": "critical",
        "cooldown_minutes": 60,
    },
    {
        "name": "Agent Outdated Version",
        "name_ru": "Агент устаревшая версия",
        "description": "Agent is running an outdated version",
        "description_ru": "Агент работает на устаревшей версии",
        "category": "agent",
        "condition_type": "agent_outdated",
        "condition_params": {},
        "severity": "info",
        "cooldown_minutes": 1440,
    },
]


# ---------------------------------------------------------------------------
# Seed built-in rules
# ---------------------------------------------------------------------------

async def seed_builtin_rules(db: AsyncSession) -> int:
    """
    Create built-in alert rules if they do not already exist.

    Matches rules by name. Existing rules are not modified.

    Args:
        db: Async database session.

    Returns:
        Number of newly created rules.
    """
    result = await db.execute(
        select(AlertRule.name).where(AlertRule.is_builtin == True)  # noqa: E712
    )
    existing_names = set(result.scalars().all())

    created = 0
    for rule_def in BUILTIN_RULES:
        if rule_def["name"] in existing_names:
            continue

        rule = AlertRule(
            name=rule_def["name"],
            name_ru=rule_def.get("name_ru"),
            description=rule_def.get("description"),
            description_ru=rule_def.get("description_ru"),
            category=rule_def["category"],
            condition_type=rule_def["condition_type"],
            condition_params=rule_def["condition_params"],
            severity=rule_def["severity"],
            is_builtin=True,
            is_enabled=True,
            notify_telegram=True,
            cooldown_minutes=rule_def.get("cooldown_minutes", 60),
        )
        db.add(rule)
        created += 1

    if created > 0:
        await db.flush()
        logger.info("Seeded %d built-in alert rules", created)

    return created


# ---------------------------------------------------------------------------
# Rule evaluation functions
# ---------------------------------------------------------------------------

class _RuleMatch:
    """Represents a single matched alert condition."""

    __slots__ = ("title", "message", "context")

    def __init__(self, title: str, message: str, context: dict | None = None):
        self.title = title
        self.message = message
        self.context = context or {}


async def _load_server_components(db: AsyncSession, server: Server) -> dict:
    """Load all RAID components for the server in a single pass."""
    ctrl_result = await db.execute(
        select(Controller).where(Controller.server_id == server.id)
    )
    controllers = ctrl_result.scalars().all()

    controller_ids = [c.id for c in controllers]

    bbu_result = await db.execute(
        select(BbuUnit).where(BbuUnit.controller_id.in_(controller_ids))
    ) if controller_ids else None
    bbus = bbu_result.scalars().all() if bbu_result else []

    vd_result = await db.execute(
        select(VirtualDrive).where(VirtualDrive.controller_id.in_(controller_ids))
    ) if controller_ids else None
    virtual_drives = vd_result.scalars().all() if vd_result else []

    pd_result = await db.execute(
        select(PhysicalDrive).where(PhysicalDrive.controller_id.in_(controller_ids))
    ) if controller_ids else None
    physical_drives = pd_result.scalars().all() if pd_result else []

    # Build lookup: controller DB id -> controller_id (numeric)
    ctrl_id_map = {c.id: c.controller_id for c in controllers}

    return {
        "controllers": controllers,
        "bbus": bbus,
        "virtual_drives": virtual_drives,
        "physical_drives": physical_drives,
        "ctrl_id_map": ctrl_id_map,
    }


def _eval_vd_state(rule: AlertRule, vd: VirtualDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a VD is in one of the specified bad states."""
    states = rule.condition_params.get("states", [])
    vd_state = (vd.state or "").strip().lower()
    if vd_state in states:
        return _RuleMatch(
            title=f"{rule.name}: VD/{vd.vd_id} ({vd.raid_type})",
            message=f"Virtual drive {vd.vd_id} is in state '{vd.state}' (RAID {vd.raid_type}, size: {vd.size or 'N/A'})",
            context={"controller_id": ctrl_num, "vd_id": vd.vd_id, "state": vd.state},
        )
    return None


def _eval_vd_state_not_in(rule: AlertRule, vd: VirtualDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a VD is NOT in the healthy states list."""
    healthy = rule.condition_params.get("healthy_states", [])
    vd_state = (vd.state or "").strip().lower()
    # Skip if already matched by specific state rules (degraded, offline, etc.)
    skip_states = ["degraded", "dgrd", "partially_degraded", "pdgd", "offline", "offln", "rebuilding", "rbld"]
    if vd_state in skip_states:
        return None
    if vd_state not in healthy:
        return _RuleMatch(
            title=f"{rule.name}: VD/{vd.vd_id}",
            message=f"Virtual drive {vd.vd_id} state is '{vd.state}', expected one of: {', '.join(healthy)}",
            context={"controller_id": ctrl_num, "vd_id": vd.vd_id, "state": vd.state},
        )
    return None


def _eval_vd_cache_wt(rule: AlertRule, vd: VirtualDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a VD cache policy contains WT pattern."""
    patterns = rule.condition_params.get("cache_patterns", [])
    cache = (vd.cache_policy or "").strip().lower()
    for pattern in patterns:
        if pattern in cache:
            return _RuleMatch(
                title=f"{rule.name}: VD/{vd.vd_id}",
                message=f"Virtual drive {vd.vd_id} cache policy is '{vd.cache_policy}'",
                context={"controller_id": ctrl_num, "vd_id": vd.vd_id, "cache_policy": vd.cache_policy},
            )
    return None


def _eval_pd_state(rule: AlertRule, pd: PhysicalDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a PD is in one of the specified states."""
    states = rule.condition_params.get("states", [])
    pd_state = (pd.state or "").strip().lower()
    if pd_state in states:
        return _RuleMatch(
            title=f"{rule.name}: PD [{pd.enclosure_id}:{pd.slot_number}]",
            message=(
                f"Physical drive [{pd.enclosure_id}:{pd.slot_number}] is in state '{pd.state}' "
                f"(model: {pd.model or 'N/A'}, serial: {pd.serial_number or 'N/A'})"
            ),
            context={
                "controller_id": ctrl_num,
                "pd_enclosure": pd.enclosure_id,
                "pd_slot": pd.slot_number,
                "state": pd.state,
            },
        )
    return None


def _eval_pd_counter_gt(rule: AlertRule, pd: PhysicalDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a PD counter exceeds the threshold."""
    field = rule.condition_params.get("field")
    threshold = rule.condition_params.get("threshold", 0)
    value = getattr(pd, field, None) if field else None
    if value is not None and value > threshold:
        return _RuleMatch(
            title=f"{rule.name}: PD [{pd.enclosure_id}:{pd.slot_number}]",
            message=(
                f"Physical drive [{pd.enclosure_id}:{pd.slot_number}] {field}={value} "
                f"(threshold: >{threshold}, model: {pd.model or 'N/A'})"
            ),
            context={
                "controller_id": ctrl_num,
                "pd_enclosure": pd.enclosure_id,
                "pd_slot": pd.slot_number,
                "field": field,
                "value": value,
                "threshold": threshold,
            },
        )
    return None


def _eval_pd_smart_alert(rule: AlertRule, pd: PhysicalDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a PD has SMART alert flagged."""
    if pd.smart_alert:
        return _RuleMatch(
            title=f"{rule.name}: PD [{pd.enclosure_id}:{pd.slot_number}]",
            message=(
                f"Physical drive [{pd.enclosure_id}:{pd.slot_number}] has SMART alert "
                f"(model: {pd.model or 'N/A'}, serial: {pd.serial_number or 'N/A'})"
            ),
            context={
                "controller_id": ctrl_num,
                "pd_enclosure": pd.enclosure_id,
                "pd_slot": pd.slot_number,
            },
        )
    return None


def _eval_pd_temp_gt(rule: AlertRule, pd: PhysicalDrive, ctrl_num: int) -> _RuleMatch | None:
    """Check if a PD temperature exceeds threshold."""
    threshold = rule.condition_params.get("threshold", 55)
    if pd.temperature is not None and pd.temperature > threshold:
        return _RuleMatch(
            title=f"{rule.name}: PD [{pd.enclosure_id}:{pd.slot_number}]",
            message=(
                f"Physical drive [{pd.enclosure_id}:{pd.slot_number}] temperature is "
                f"{pd.temperature}C (threshold: >{threshold}C)"
            ),
            context={
                "controller_id": ctrl_num,
                "pd_enclosure": pd.enclosure_id,
                "pd_slot": pd.slot_number,
                "temperature": pd.temperature,
                "threshold": threshold,
            },
        )
    return None


def _eval_ctrl_status_not_ok(rule: AlertRule, ctrl: Controller) -> _RuleMatch | None:
    """Check if controller status is not healthy."""
    healthy = rule.condition_params.get("healthy_states", [])
    status = (ctrl.status or "").strip().lower()
    if status and status not in healthy:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl.controller_id}",
            message=(
                f"Controller #{ctrl.controller_id} status is '{ctrl.status}' "
                f"(model: {ctrl.model or 'N/A'})"
            ),
            context={"controller_id": ctrl.controller_id, "status": ctrl.status},
        )
    return None


def _eval_ctrl_roc_temp_gt(rule: AlertRule, ctrl: Controller) -> _RuleMatch | None:
    """Check if controller ROC temperature exceeds threshold."""
    threshold = rule.condition_params.get("threshold", 80)
    if ctrl.roc_temperature is not None and ctrl.roc_temperature > threshold:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl.controller_id}",
            message=(
                f"Controller #{ctrl.controller_id} ROC temperature is "
                f"{ctrl.roc_temperature}C (threshold: >{threshold}C)"
            ),
            context={
                "controller_id": ctrl.controller_id,
                "roc_temperature": ctrl.roc_temperature,
                "threshold": threshold,
            },
        )
    return None


def _eval_ctrl_memory_errors(rule: AlertRule, ctrl: Controller) -> _RuleMatch | None:
    """Check if controller has uncorrectable memory errors."""
    field = rule.condition_params.get("field", "memory_uncorrectable_errors")
    threshold = rule.condition_params.get("threshold", 0)
    value = getattr(ctrl, field, 0) or 0
    if value > threshold:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl.controller_id}",
            message=(
                f"Controller #{ctrl.controller_id} has {value} uncorrectable memory errors "
                f"(model: {ctrl.model or 'N/A'})"
            ),
            context={
                "controller_id": ctrl.controller_id,
                "field": field,
                "value": value,
            },
        )
    return None


def _eval_bbu_state_not_ok(rule: AlertRule, bbu: BbuUnit, ctrl_num: int) -> _RuleMatch | None:
    """Check if BBU state is not healthy."""
    healthy = rule.condition_params.get("healthy_states", [])
    state = (bbu.state or "").strip().lower()
    if state and state not in healthy:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl_num}",
            message=f"BBU on controller #{ctrl_num} state is '{bbu.state}' (type: {bbu.bbu_type or 'N/A'})",
            context={"controller_id": ctrl_num, "bbu_state": bbu.state},
        )
    return None


def _eval_bbu_replacement(rule: AlertRule, bbu: BbuUnit, ctrl_num: int) -> _RuleMatch | None:
    """Check if BBU needs replacement."""
    if bbu.replacement_needed:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl_num}",
            message=f"BBU on controller #{ctrl_num} needs replacement (type: {bbu.bbu_type or 'N/A'})",
            context={"controller_id": ctrl_num, "replacement_needed": True},
        )
    return None


def _eval_bbu_temp_gt(rule: AlertRule, bbu: BbuUnit, ctrl_num: int) -> _RuleMatch | None:
    """Check if BBU temperature exceeds threshold."""
    threshold = rule.condition_params.get("threshold", 50)
    if bbu.temperature is not None and bbu.temperature > threshold:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl_num}",
            message=(
                f"BBU on controller #{ctrl_num} temperature is {bbu.temperature}C "
                f"(threshold: >{threshold}C)"
            ),
            context={
                "controller_id": ctrl_num,
                "bbu_temperature": bbu.temperature,
                "threshold": threshold,
            },
        )
    return None


def _eval_bbu_learn_failed(rule: AlertRule, bbu: BbuUnit, ctrl_num: int) -> _RuleMatch | None:
    """Check if BBU learn cycle has failed."""
    failed_states = rule.condition_params.get("failed_states", [])
    learn_status = (bbu.learn_cycle_status or "").strip().lower()
    if learn_status in failed_states:
        return _RuleMatch(
            title=f"{rule.name}: Controller #{ctrl_num}",
            message=(
                f"BBU learn cycle on controller #{ctrl_num} status: "
                f"'{bbu.learn_cycle_status}'"
            ),
            context={"controller_id": ctrl_num, "learn_cycle_status": bbu.learn_cycle_status},
        )
    return None


def _eval_agent_offline(rule: AlertRule, server: Server) -> _RuleMatch | None:
    """Check if the agent has been offline longer than the threshold."""
    minutes = rule.condition_params.get("minutes", 20)
    if server.last_seen is None:
        return _RuleMatch(
            title=f"{rule.name}: {server.hostname}",
            message=f"Agent on {server.hostname} has never reported",
            context={"minutes": minutes},
        )
    now = datetime.now(timezone.utc)
    last_seen = server.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    delta = now - last_seen
    if delta > timedelta(minutes=minutes):
        return _RuleMatch(
            title=f"{rule.name}: {server.hostname}",
            message=(
                f"Agent on {server.hostname} last reported "
                f"{int(delta.total_seconds() // 60)} minutes ago"
            ),
            context={"minutes_offline": int(delta.total_seconds() // 60), "threshold": minutes},
        )
    return None


async def _eval_agent_outdated(
    rule: AlertRule, server: Server, db: AsyncSession
) -> _RuleMatch | None:
    """Check if the agent version is outdated compared to the current package."""
    from app.models import AgentPackage

    if not server.agent_version:
        return None

    result = await db.execute(
        select(AgentPackage).where(AgentPackage.is_current == True)  # noqa: E712
    )
    current_pkg = result.scalar_one_or_none()
    if current_pkg is None:
        return None

    if server.agent_version != current_pkg.version:
        return _RuleMatch(
            title=f"{rule.name}: {server.hostname}",
            message=(
                f"Agent on {server.hostname} is running v{server.agent_version}, "
                f"current version is v{current_pkg.version}"
            ),
            context={
                "agent_version": server.agent_version,
                "current_version": current_pkg.version,
            },
        )
    return None


# ---------------------------------------------------------------------------
# Rule evaluation dispatcher
# ---------------------------------------------------------------------------

async def _evaluate_rule(
    db: AsyncSession,
    rule: AlertRule,
    server: Server,
    components: dict,
) -> list[_RuleMatch]:
    """
    Evaluate a single rule against a server and its components.

    Returns a list of matches (one per offending component).
    """
    matches: list[_RuleMatch] = []
    ctype = rule.condition_type
    ctrl_id_map = components["ctrl_id_map"]

    # --- Virtual Drive rules ---
    if ctype in ("vd_state", "vd_state_not_in", "vd_cache_wt"):
        for vd in components["virtual_drives"]:
            ctrl_num = ctrl_id_map.get(vd.controller_id, 0)
            match = None
            if ctype == "vd_state":
                match = _eval_vd_state(rule, vd, ctrl_num)
            elif ctype == "vd_state_not_in":
                match = _eval_vd_state_not_in(rule, vd, ctrl_num)
            elif ctype == "vd_cache_wt":
                match = _eval_vd_cache_wt(rule, vd, ctrl_num)
            if match:
                matches.append(match)

    # --- Physical Drive rules ---
    elif ctype in ("pd_state", "pd_counter_gt", "pd_smart_alert", "pd_temp_gt"):
        for pd in components["physical_drives"]:
            ctrl_num = ctrl_id_map.get(pd.controller_id, 0)
            match = None
            if ctype == "pd_state":
                match = _eval_pd_state(rule, pd, ctrl_num)
            elif ctype == "pd_counter_gt":
                match = _eval_pd_counter_gt(rule, pd, ctrl_num)
            elif ctype == "pd_smart_alert":
                match = _eval_pd_smart_alert(rule, pd, ctrl_num)
            elif ctype == "pd_temp_gt":
                match = _eval_pd_temp_gt(rule, pd, ctrl_num)
            if match:
                matches.append(match)

    # --- Controller rules ---
    elif ctype in ("ctrl_status_not_ok", "ctrl_roc_temp_gt", "ctrl_memory_errors"):
        for ctrl in components["controllers"]:
            match = None
            if ctype == "ctrl_status_not_ok":
                match = _eval_ctrl_status_not_ok(rule, ctrl)
            elif ctype == "ctrl_roc_temp_gt":
                match = _eval_ctrl_roc_temp_gt(rule, ctrl)
            elif ctype == "ctrl_memory_errors":
                match = _eval_ctrl_memory_errors(rule, ctrl)
            if match:
                matches.append(match)

    # --- BBU rules ---
    elif ctype in ("bbu_state_not_ok", "bbu_replacement", "bbu_temp_gt", "bbu_learn_failed"):
        for bbu in components["bbus"]:
            ctrl_num = ctrl_id_map.get(bbu.controller_id, 0)
            match = None
            if ctype == "bbu_state_not_ok":
                match = _eval_bbu_state_not_ok(rule, bbu, ctrl_num)
            elif ctype == "bbu_replacement":
                match = _eval_bbu_replacement(rule, bbu, ctrl_num)
            elif ctype == "bbu_temp_gt":
                match = _eval_bbu_temp_gt(rule, bbu, ctrl_num)
            elif ctype == "bbu_learn_failed":
                match = _eval_bbu_learn_failed(rule, bbu, ctrl_num)
            if match:
                matches.append(match)

    # --- Agent rules ---
    elif ctype == "agent_offline":
        match = _eval_agent_offline(rule, server)
        if match:
            matches.append(match)

    elif ctype == "agent_outdated":
        match = await _eval_agent_outdated(rule, server, db)
        if match:
            matches.append(match)

    else:
        logger.warning("Unknown condition_type '%s' for rule '%s'", ctype, rule.name)

    return matches


# ---------------------------------------------------------------------------
# Cooldown check
# ---------------------------------------------------------------------------

async def _check_cooldown(
    db: AsyncSession,
    rule: AlertRule,
    server_id: uuid.UUID,
    context: dict,
) -> bool:
    """
    Check if the cooldown period has elapsed for a specific alert.

    Returns True if the alert should be suppressed (within cooldown).
    """
    cooldown_cutoff = datetime.now(timezone.utc) - timedelta(minutes=rule.cooldown_minutes)

    stmt = select(AlertHistory).where(
        and_(
            AlertHistory.rule_id == rule.id,
            AlertHistory.server_id == server_id,
            AlertHistory.created_at >= cooldown_cutoff,
        )
    )
    result = await db.execute(stmt)
    recent_alerts = result.scalars().all()

    if not recent_alerts:
        return False

    # For component-specific alerts, check context match
    ctx_keys = ["controller_id", "vd_id", "pd_enclosure", "pd_slot"]
    for alert in recent_alerts:
        if alert.context:
            if all(
                alert.context.get(k) == context.get(k)
                for k in ctx_keys
                if k in context
            ):
                return True
        elif not any(k in context for k in ctx_keys):
            return True

    return False


# ---------------------------------------------------------------------------
# Alert resolution
# ---------------------------------------------------------------------------

async def _resolve_cleared_alerts(
    db: AsyncSession,
    server: Server,
    rule: AlertRule,
    current_matches: list[_RuleMatch],
) -> None:
    """
    Resolve any open alerts for this rule+server that are no longer triggered.
    """
    result = await db.execute(
        select(AlertHistory).where(
            and_(
                AlertHistory.rule_id == rule.id,
                AlertHistory.server_id == server.id,
                AlertHistory.is_resolved == False,  # noqa: E712
            )
        )
    )
    open_alerts = result.scalars().all()

    if not open_alerts:
        return

    # Build a set of currently-firing context signatures
    def _ctx_sig(ctx: dict) -> str:
        parts = []
        for k in sorted(ctx.keys()):
            if k in ("controller_id", "vd_id", "pd_enclosure", "pd_slot"):
                parts.append(f"{k}={ctx[k]}")
        return "|".join(parts)

    active_sigs = {_ctx_sig(m.context) for m in current_matches}

    now = datetime.now(timezone.utc)
    for alert in open_alerts:
        alert_sig = _ctx_sig(alert.context or {})
        if alert_sig not in active_sigs:
            alert.is_resolved = True
            alert.resolved_at = now
            logger.info(
                "Resolved alert #%d '%s' for server %s",
                alert.id,
                alert.title,
                server.hostname,
            )
            try:
                await telegram_notifier.send_resolve_notification(alert, server)
            except Exception:
                logger.exception("Failed to send resolve notification for alert #%d", alert.id)

    await db.flush()


# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------

async def evaluate_alerts(db: AsyncSession, server: Server) -> list[AlertHistory]:
    """
    Evaluate all enabled alert rules against the given server.

    1. Loads all enabled rules.
    2. Loads all server components.
    3. For each rule, evaluates conditions.
    4. Creates new AlertHistory entries (respecting cooldown).
    5. Resolves alerts whose conditions have cleared.
    6. Sends Telegram notifications for new alerts.

    Args:
        db: Async database session.
        server: Server instance to evaluate.

    Returns:
        List of newly created AlertHistory entries.
    """
    result = await db.execute(
        select(AlertRule).where(AlertRule.is_enabled == True)  # noqa: E712
    )
    rules = result.scalars().all()

    if not rules:
        logger.debug("No enabled alert rules, skipping evaluation")
        return []

    components = await _load_server_components(db, server)
    new_alerts: list[AlertHistory] = []

    for rule in rules:
        try:
            matches = await _evaluate_rule(db, rule, server, components)
        except Exception:
            logger.exception("Error evaluating rule '%s' for server %s", rule.name, server.hostname)
            continue

        # Resolve alerts whose condition has cleared
        try:
            await _resolve_cleared_alerts(db, server, rule, matches)
        except Exception:
            logger.exception(
                "Error resolving cleared alerts for rule '%s' on server %s",
                rule.name,
                server.hostname,
            )

        # Create new alerts for current matches
        for match in matches:
            # Check cooldown
            suppressed = await _check_cooldown(db, rule, server.id, match.context)
            if suppressed:
                continue

            alert = AlertHistory(
                rule_id=rule.id,
                server_id=server.id,
                severity=rule.severity,
                title=match.title,
                message=match.message,
                context=match.context,
                is_resolved=False,
                notified_telegram=False,
            )
            db.add(alert)
            await db.flush()

            new_alerts.append(alert)
            logger.info(
                "New alert [%s] '%s' for server %s",
                rule.severity,
                match.title,
                server.hostname,
            )

            # Send Telegram notification
            if rule.notify_telegram:
                try:
                    sent = await telegram_notifier.send_alert(alert, server)
                    if sent:
                        alert.notified_telegram = True
                        await db.flush()
                except Exception:
                    logger.exception(
                        "Failed to send Telegram notification for alert '%s'",
                        match.title,
                    )

    if new_alerts:
        logger.info(
            "Alert evaluation complete for %s: %d new alerts",
            server.hostname,
            len(new_alerts),
        )

    return new_alerts
