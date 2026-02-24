"""
SSL certificate management service.

Handles reading certificate metadata, uploading new certificates and
private keys, and reloading nginx to apply the new configuration.
"""
import asyncio
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from app.config import settings

logger = logging.getLogger(__name__)

CERT_FILENAME = "server.crt"
KEY_FILENAME = "server.key"


def _get_ssl_dir() -> Path:
    """Return the configured nginx SSL directory path."""
    ssl_dir = Path(settings.NGINX_SSL_DIR)
    ssl_dir.mkdir(parents=True, exist_ok=True)
    return ssl_dir


def _get_cert_path() -> Path:
    """Return the full path to the SSL certificate file."""
    return _get_ssl_dir() / CERT_FILENAME


def _get_key_path() -> Path:
    """Return the full path to the SSL private key file."""
    return _get_ssl_dir() / KEY_FILENAME


def _parse_name_attribute(name: x509.Name, oid) -> str:
    """Safely extract a single attribute from an x509 Name."""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return ""


def _parse_certificate(cert_data: bytes) -> dict[str, Any]:
    """
    Parse a PEM-encoded certificate and return its metadata.

    Args:
        cert_data: Raw PEM bytes of the certificate.

    Returns:
        Dict with subject, issuer, serial, not_before, not_after,
        is_self_signed, san, fingerprint_sha256.
    """
    cert = x509.load_pem_x509_certificate(cert_data)

    subject = cert.subject
    issuer = cert.issuer

    subject_info = {
        "common_name": _parse_name_attribute(subject, NameOID.COMMON_NAME),
        "organization": _parse_name_attribute(subject, NameOID.ORGANIZATION_NAME),
        "organizational_unit": _parse_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "country": _parse_name_attribute(subject, NameOID.COUNTRY_NAME),
        "state": _parse_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME),
        "locality": _parse_name_attribute(subject, NameOID.LOCALITY_NAME),
    }

    issuer_info = {
        "common_name": _parse_name_attribute(issuer, NameOID.COMMON_NAME),
        "organization": _parse_name_attribute(issuer, NameOID.ORGANIZATION_NAME),
        "country": _parse_name_attribute(issuer, NameOID.COUNTRY_NAME),
    }

    # Subject Alternative Names
    san_list: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    except Exception:
        logger.debug("Could not parse SAN extension")

    # Fingerprint
    fingerprint = cert.fingerprint(cert.signature_hash_algorithm).hex(":")

    # Expiry calculation
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before

    now = datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)

    days_remaining = (not_after - now).days
    is_expired = days_remaining < 0
    is_self_signed = cert.issuer == cert.subject

    return {
        "subject": subject_info,
        "issuer": issuer_info,
        "serial_number": str(cert.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "is_self_signed": is_self_signed,
        "san": san_list,
        "fingerprint_sha256": fingerprint,
        "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid),
    }


async def get_cert_info() -> dict[str, Any]:
    """
    Read the current SSL certificate and return its metadata.

    Returns:
        Dict with certificate details, or a dict with 'error' key if no
        certificate is found or parsing fails.
    """
    cert_path = _get_cert_path()

    if not cert_path.exists():
        return {
            "installed": False,
            "error": "No SSL certificate found",
            "cert_path": str(cert_path),
        }

    try:
        loop = asyncio.get_running_loop()
        cert_data = await loop.run_in_executor(None, cert_path.read_bytes)
        info = await loop.run_in_executor(None, _parse_certificate, cert_data)
        info["installed"] = True
        info["cert_path"] = str(cert_path)
        info["key_path"] = str(_get_key_path())
        info["key_exists"] = _get_key_path().exists()
        return info

    except Exception as exc:
        logger.exception("Failed to parse SSL certificate at %s", cert_path)
        return {
            "installed": True,
            "error": f"Failed to parse certificate: {exc}",
            "cert_path": str(cert_path),
        }


def _validate_cert_key_pair(cert_data: bytes, key_data: bytes) -> tuple[bool, str]:
    """
    Validate that a certificate and private key form a matching pair.

    Args:
        cert_data: PEM-encoded certificate bytes.
        key_data: PEM-encoded private key bytes.

    Returns:
        Tuple of (valid: bool, message: str).
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception as exc:
        return False, f"Invalid certificate format: {exc}"

    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
    except Exception as exc:
        return False, f"Invalid private key format: {exc}"

    # Compare public keys
    try:
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_pub != key_pub:
            return False, "Certificate and private key do not match"
    except Exception as exc:
        return False, f"Could not verify key pair: {exc}"

    return True, "Certificate and key are valid and match"


def _reload_nginx() -> tuple[bool, str]:
    """
    Reload nginx to apply the new SSL certificate.

    Returns:
        Tuple of (success: bool, message: str).
    """
    try:
        # Test nginx config first
        test_result = subprocess.run(
            ["nginx", "-t"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if test_result.returncode != 0:
            error_msg = test_result.stderr.strip()
            logger.error("Nginx config test failed: %s", error_msg)
            return False, f"Nginx config test failed: {error_msg}"

        # Reload nginx
        reload_result = subprocess.run(
            ["nginx", "-s", "reload"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if reload_result.returncode != 0:
            error_msg = reload_result.stderr.strip()
            logger.error("Nginx reload failed: %s", error_msg)
            return False, f"Nginx reload failed: {error_msg}"

        logger.info("Nginx reloaded successfully with new SSL certificate")
        return True, "Nginx reloaded successfully"

    except FileNotFoundError:
        logger.warning("Nginx binary not found, skipping reload")
        return True, "Certificate saved (nginx not found, manual reload required)"
    except subprocess.TimeoutExpired:
        logger.error("Nginx reload timed out")
        return False, "Nginx reload timed out"
    except Exception as exc:
        logger.exception("Failed to reload nginx")
        return False, f"Failed to reload nginx: {exc}"


async def upload_cert(cert_data: bytes, key_data: bytes) -> dict[str, Any]:
    """
    Upload and install a new SSL certificate and private key.

    1. Validates the certificate and key formats.
    2. Verifies the cert-key pair matches.
    3. Writes files to the nginx SSL directory.
    4. Reloads nginx.

    Args:
        cert_data: PEM-encoded certificate bytes.
        key_data: PEM-encoded private key bytes.

    Returns:
        Dict with 'success', 'message', and optionally 'cert_info'.
    """
    loop = asyncio.get_running_loop()

    # Validate cert-key pair
    valid, message = await loop.run_in_executor(
        None, _validate_cert_key_pair, cert_data, key_data
    )

    if not valid:
        return {"success": False, "message": message}

    cert_path = _get_cert_path()
    key_path = _get_key_path()

    # Backup existing files
    try:
        if cert_path.exists():
            backup_cert = cert_path.with_suffix(".crt.bak")
            await loop.run_in_executor(None, cert_path.rename, backup_cert)
            logger.info("Backed up existing certificate to %s", backup_cert)

        if key_path.exists():
            backup_key = key_path.with_suffix(".key.bak")
            await loop.run_in_executor(None, key_path.rename, backup_key)
            logger.info("Backed up existing key to %s", backup_key)
    except Exception:
        logger.warning("Could not backup existing SSL files")

    # Write new files
    try:
        # Write certificate
        await loop.run_in_executor(None, cert_path.write_bytes, cert_data)
        await loop.run_in_executor(None, os.chmod, str(cert_path), 0o644)

        # Write private key with restricted permissions
        await loop.run_in_executor(None, key_path.write_bytes, key_data)
        await loop.run_in_executor(None, os.chmod, str(key_path), 0o600)

        logger.info("SSL certificate and key written to %s", _get_ssl_dir())

    except Exception as exc:
        logger.exception("Failed to write SSL files")
        return {"success": False, "message": f"Failed to write files: {exc}"}

    # Reload nginx
    reload_ok, reload_msg = await loop.run_in_executor(None, _reload_nginx)

    # Parse the new certificate for response
    try:
        cert_info = await loop.run_in_executor(None, _parse_certificate, cert_data)
    except Exception:
        cert_info = {}

    return {
        "success": True,
        "message": f"SSL certificate installed. {reload_msg}",
        "nginx_reloaded": reload_ok,
        "cert_info": cert_info,
    }
