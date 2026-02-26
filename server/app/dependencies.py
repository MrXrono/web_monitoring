import logging
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import bcrypt as _bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models.api_key import ApiKey
from app.models.server import Server
from app.models.user import User

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"

bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session, closing it when done."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate the JWT Bearer token from the Authorization header.
    Returns the authenticated User ORM object.
    Raises 401 if the token is missing, invalid, expired, or the user is not found/inactive.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return user


async def verify_agent_key(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Server:
    """
    Validate the agent API key from the Authorization header.
    The key is checked against bcrypt hashes stored in the api_keys table.
    Returns the associated Server ORM object.
    Raises 401 if the key is missing, invalid, or the server is not found.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_key = credentials.credentials

    # Extract prefix (first 8 chars) for quick lookup
    key_prefix = raw_key[:8] if len(raw_key) >= 8 else raw_key

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.key_prefix == key_prefix, ApiKey.is_active.is_(True))
    )
    api_key_records = result.scalars().all()

    matched_api_key = None
    for api_key_record in api_key_records:
        try:
            if _bcrypt.checkpw(raw_key.encode("utf-8"), api_key_record.key_hash.encode("utf-8")):
                matched_api_key = api_key_record
                break
        except Exception:
            continue

    if matched_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at
    from datetime import datetime
    from app.config import MSK
    matched_api_key.last_used_at = datetime.now(MSK)
    await db.commit()

    # Load associated server
    result = await db.execute(
        select(Server).where(Server.id == matched_api_key.server_id)
    )
    server = result.scalar_one_or_none()

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Server not found for this API key",
        )

    return server


def get_locale(request: Request, user: User | None = None) -> str:
    """
    Determine the preferred language for responses.
    Priority: user preference > cookie > Accept-Language header > default 'en'.
    """
    # 1. User preference (if authenticated)
    if user is not None and user.language:
        return user.language

    # 2. Cookie
    lang_cookie = request.cookies.get("language")
    if lang_cookie and lang_cookie in ("en", "ru"):
        return lang_cookie

    # 3. Accept-Language header
    accept_lang = request.headers.get("Accept-Language", "")
    if "ru" in accept_lang.lower():
        return "ru"

    return "en"
