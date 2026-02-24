import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from jose import jwt
import bcrypt as _bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_db, get_current_user, JWT_ALGORITHM
from app.models.user import User
from app.models.setting import Setting
from app.services.encryption import decrypt_value
from app.schemas.auth import LoginRequest, LoginResponse, UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

ACCESS_TOKEN_EXPIRE_HOURS = 24


def _create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


async def _try_ldap_auth(username: str, password: str, db: AsyncSession) -> User | None:
    """
    Attempt LDAP authentication using settings from the database.
    Returns a User object on success, None on failure.
    """
    try:
        import ldap3
    except ImportError:
        logger.warning("ldap3 not installed, LDAP auth unavailable")
        return None

    # Load LDAP settings
    ldap_keys = [
        "ldap_enabled", "ldap_server_url", "ldap_bind_dn",
        "ldap_bind_password", "ldap_search_base", "ldap_user_filter",
        "ldap_display_name_attr", "ldap_email_attr",
    ]
    result = await db.execute(
        select(Setting).where(Setting.key.in_(ldap_keys))
    )
    ldap_settings = {s.key: s for s in result.scalars().all()}

    enabled_setting = ldap_settings.get("ldap_enabled")
    if not enabled_setting or enabled_setting.value != "true":
        return None

    server_url = ldap_settings.get("ldap_server_url")
    bind_dn = ldap_settings.get("ldap_bind_dn")
    bind_password_setting = ldap_settings.get("ldap_bind_password")
    search_base = ldap_settings.get("ldap_search_base")
    user_filter_tmpl = ldap_settings.get("ldap_user_filter")

    if not all([server_url, bind_dn, search_base]):
        logger.warning("LDAP configuration incomplete")
        return None

    server_url_val = server_url.value
    bind_dn_val = bind_dn.value
    search_base_val = search_base.value
    user_filter_val = user_filter_tmpl.value if user_filter_tmpl else f"(sAMAccountName={username})"
    user_filter_val = user_filter_val.replace("{username}", username)

    # Decrypt bind password if encrypted
    bind_pass = ""
    if bind_password_setting:
        if bind_password_setting.is_encrypted and bind_password_setting.value:
            try:
                bind_pass = decrypt_value(bind_password_setting.value)
            except Exception:
                logger.error("Failed to decrypt LDAP bind password")
                return None
        else:
            bind_pass = bind_password_setting.value or ""

    display_name_attr = "displayName"
    email_attr = "mail"
    if ldap_settings.get("ldap_display_name_attr"):
        display_name_attr = ldap_settings["ldap_display_name_attr"].value or display_name_attr
    if ldap_settings.get("ldap_email_attr"):
        email_attr = ldap_settings["ldap_email_attr"].value or email_attr

    try:
        server = ldap3.Server(server_url_val, get_info=ldap3.ALL, connect_timeout=10)

        # Bind with service account
        conn = ldap3.Connection(server, user=bind_dn_val, password=bind_pass, auto_bind=True)

        # Search for the user
        conn.search(
            search_base_val,
            user_filter_val,
            search_scope=ldap3.SUBTREE,
            attributes=[display_name_attr, email_attr],
        )

        if not conn.entries:
            conn.unbind()
            return None

        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn

        # Try to bind as the user to verify password
        user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()
        conn.unbind()

        # Extract attributes
        display_name = str(getattr(user_entry, display_name_attr, username))
        email = str(getattr(user_entry, email_attr, ""))

        # Find or create local user record
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        if user is None:
            user = User(
                username=username,
                display_name=display_name if display_name != "[]" else username,
                email=email if email != "[]" else None,
                auth_source="ldap",
                is_active=True,
                is_admin=False,
            )
            db.add(user)
        else:
            user.display_name = display_name if display_name != "[]" else user.display_name
            user.email = email if email != "[]" else user.email
            user.auth_source = "ldap"

        user.last_login = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(user)
        return user

    except ldap3.core.exceptions.LDAPBindError:
        logger.info("LDAP bind failed for user %s", username)
        return None
    except Exception:
        logger.exception("LDAP authentication error")
        return None


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate via local password or LDAP.
    Returns a JWT access token on success.
    """
    # 1. Try local auth first
    result = await db.execute(
        select(User).where(User.username == payload.username)
    )
    user = result.scalar_one_or_none()

    authenticated = False

    if user and user.auth_source == "local" and user.password_hash:
        if _bcrypt.checkpw(payload.password.encode("utf-8"), user.password_hash.encode("utf-8")):
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is disabled",
                )
            # Check local admin expiry
            if user.local_admin_expires and user.local_admin_expires < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Local admin account has expired. Configure LDAP authentication.",
                )
            authenticated = True
            user.last_login = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(user)

    # 2. Try LDAP if local auth failed
    if not authenticated:
        ldap_user = await _try_ldap_auth(payload.username, payload.password, db)
        if ldap_user:
            user = ldap_user
            authenticated = True

    if not authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create JWT
    access_token = _create_access_token(
        data={"sub": user.username, "uid": str(user.id), "admin": user.is_admin}
    )

    # Set language cookie
    response.set_cookie(
        key="language",
        value=user.language,
        max_age=86400 * 365,
        httponly=False,
        samesite="lax",
    )

    return LoginResponse(
        access_token=access_token,
        username=user.username,
        display_name=user.display_name,
        language=user.language,
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    response: Response,
    user: User = Depends(get_current_user),
):
    """
    Logout the current user.
    Since JWTs are stateless, this primarily clears the language cookie.
    Client should discard the token.
    """
    response.delete_cookie("language")
    return {"status": "ok", "message": "Logged out"}


@router.get("/me", response_model=UserInfo)
async def get_me(
    user: User = Depends(get_current_user),
):
    """Return information about the currently authenticated user."""
    return UserInfo(
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        auth_source=user.auth_source,
        language=user.language,
        is_admin=user.is_admin,
    )
