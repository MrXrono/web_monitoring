from pydantic import BaseModel
from typing import Optional


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    display_name: Optional[str] = None
    language: str = "en"


class UserInfo(BaseModel):
    username: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    auth_source: str
    language: str
    is_admin: bool
