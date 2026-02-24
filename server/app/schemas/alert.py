from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AlertRuleResponse(BaseModel):
    id: str
    name: str
    name_ru: Optional[str] = None
    description: Optional[str] = None
    description_ru: Optional[str] = None
    category: str
    condition_type: str
    condition_params: dict
    severity: str
    is_enabled: bool
    is_builtin: bool
    notify_telegram: bool
    cooldown_minutes: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AlertRuleUpdateRequest(BaseModel):
    is_enabled: Optional[bool] = None
    severity: Optional[str] = None
    notify_telegram: Optional[bool] = None
    cooldown_minutes: Optional[int] = None
    condition_params: Optional[dict] = None


class AlertRuleListResponse(BaseModel):
    items: list[AlertRuleResponse]
    total: int


class AlertHistoryItem(BaseModel):
    id: int
    rule_id: Optional[str] = None
    server_id: Optional[str] = None
    server_hostname: Optional[str] = None
    severity: str
    title: str
    message: str
    context: Optional[dict] = None
    is_resolved: bool
    resolved_at: Optional[datetime] = None
    notified_telegram: bool
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AlertHistoryListResponse(BaseModel):
    items: list[AlertHistoryItem]
    total: int
    page: int
    per_page: int
    pages: int


class AlertSummaryResponse(BaseModel):
    total: int = 0
    active: int = 0
    resolved: int = 0
    critical: int = 0
    warning: int = 0
    info: int = 0
