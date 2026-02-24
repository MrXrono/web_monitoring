from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class SettingItem(BaseModel):
    key: str
    value: Optional[str] = None
    is_encrypted: bool = False
    description: Optional[str] = None
    category: Optional[str] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class SettingsCategoryResponse(BaseModel):
    category: str
    settings: list[SettingItem]


class SettingsUpdateRequest(BaseModel):
    settings: dict[str, Optional[str]]


class SettingsUpdateResponse(BaseModel):
    updated: list[str]
    message: str = "Settings updated"


class SSLUploadResponse(BaseModel):
    message: str
    cert_filename: Optional[str] = None
    key_filename: Optional[str] = None


class LdapTestRequest(BaseModel):
    server_url: Optional[str] = None
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    search_base: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class LdapTestResponse(BaseModel):
    success: bool
    message: str
    user_dn: Optional[str] = None


class TelegramTestRequest(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
    message: str = "Test notification from RAID Monitor"


class TelegramTestResponse(BaseModel):
    success: bool
    message: str


class AgentPackageResponse(BaseModel):
    id: str
    version: str
    filename: str
    file_hash_sha256: str
    file_size: int
    release_notes: Optional[str] = None
    is_current: bool
    uploaded_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class LogCollectResponse(BaseModel):
    message: str
    servers_count: int = 0


class LogUploadExternalResponse(BaseModel):
    success: bool
    message: str
    url: Optional[str] = None
