"""
Fernet-based encryption service for sensitive values.

Used to encrypt/decrypt secrets stored in the database such as
Telegram bot tokens and LDAP bind passwords.
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

logger = logging.getLogger(__name__)


def _derive_key(raw_key: str) -> bytes:
    """Derive a 32-byte URL-safe base64 Fernet key from an arbitrary string."""
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    """Return a Fernet instance using the configured ENCRYPTION_KEY."""
    key = _derive_key(settings.ENCRYPTION_KEY)
    return Fernet(key)


def encrypt_value(value: str) -> str:
    """
    Encrypt a plaintext string and return the ciphertext as a UTF-8 string.

    Args:
        value: The plaintext value to encrypt.

    Returns:
        Fernet-encrypted ciphertext encoded as a UTF-8 string.

    Raises:
        ValueError: If the value is empty or None.
    """
    if not value:
        raise ValueError("Cannot encrypt an empty or None value")

    try:
        f = _get_fernet()
        token = f.encrypt(value.encode("utf-8"))
        return token.decode("utf-8")
    except Exception:
        logger.exception("Failed to encrypt value")
        raise


def decrypt_value(encrypted: str) -> str:
    """
    Decrypt a Fernet-encrypted string back to plaintext.

    Args:
        encrypted: The Fernet ciphertext string.

    Returns:
        The decrypted plaintext string.

    Raises:
        ValueError: If the encrypted value is empty or None.
        InvalidToken: If decryption fails (wrong key or tampered data).
    """
    if not encrypted:
        raise ValueError("Cannot decrypt an empty or None value")

    try:
        f = _get_fernet()
        plaintext = f.decrypt(encrypted.encode("utf-8"))
        return plaintext.decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt value: invalid token or wrong encryption key")
        raise
    except Exception:
        logger.exception("Unexpected error during decryption")
        raise
