"""Security configuration and constants."""

import os
import logging
from typing import Optional

logger = logging.getLogger("linkcheck.security.config")


class SecurityConfig:
    """Centralized security configuration."""

    # ── AUTHENTICATION ────────────────────────────────────────────────
    TOKEN_ALGORITHM = "HS256"
    TOKEN_EXPIRY_HOURS = 24
    TOKEN_LENGTH = 32  # bytes
    MAX_TOKEN_AGE = 86400  # seconds (1 day)

    # ── PASSWORDS ─────────────────────────────────────────────────────
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_HASH_ITERATIONS = 100000  # PBKDF2
    PASSWORD_HASH_ALGORITHM = "sha256"
    HASH_SALT_LENGTH = 32  # bytes

    # ── ENCRYPTION ────────────────────────────────────────────────────
    ENCRYPTION_ALGORITHM = "Fernet"  # symmetric
    ENCRYPTION_KEY_LENGTH = 32  # bytes

    # ── RATE LIMITING ─────────────────────────────────────────────────
    RATE_LIMIT_ANALYZE = "30 per minute"
    RATE_LIMIT_ADMIN = "10 per minute"
    RATE_LIMIT_AUTH = "5 per minute"
    RATE_LIMIT_FEEDBACK = "10 per minute"
    RATE_LIMIT_SCREENSHOT = "60 per minute"

    # ── INPUT VALIDATION ──────────────────────────────────────────────
    MAX_URL_LENGTH = 2048
    MAX_HOSTNAME_LENGTH = 255
    MAX_JSON_PAYLOAD_SIZE = 1_000_000  # 1 MB
    MAX_COMMENT_LENGTH = 5000

    # ── TIMEOUT LIMITS ────────────────────────────────────────────────
    REQUEST_TIMEOUT = 30  # seconds
    THREAT_INTEL_TIMEOUT = 8  # seconds
    SCREENSHOT_TIMEOUT = 15  # seconds

    # ── SECURITY HEADERS ──────────────────────────────────────────────
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    # ── THREAT LEVELS ────────────────────────────────────────────────
    THREAT_LEVELS = {
        "safe": 0,
        "info": 1,
        "warn": 2,
        "danger": 3,
    }

    # ── LOG LEVELS ────────────────────────────────────────────────────
    LOG_LEVEL_SECURITY = "WARNING"
    LOG_LEVEL_AUTH = "INFO"
    LOG_LEVEL_REQUEST = "INFO"

    @classmethod
    def validate(cls) -> bool:
        """
        Validate security configuration at startup.
        
        Returns:
            True if valid, raises Exception otherwise
        """
        errors = []

        # Check environment variables
        secret_key = os.environ.get("SECRET_KEY", "")
        if not secret_key or secret_key == "dev-only-change-me":
            errors.append("SECRET_KEY not set or using default dev key (CRITICAL)")

        flask_debug = os.environ.get("FLASK_DEBUG", "false").lower()
        if flask_debug == "true":
            errors.append("FLASK_DEBUG=true in production (CRITICAL)")

        flask_env = os.environ.get("FLASK_ENV", "production")
        if flask_env != "production":
            errors.append(f"FLASK_ENV={flask_env} (not production)")

        # Check feedback admin token
        admin_token = os.environ.get("FEEDBACK_ADMIN_TOKEN", "")
        if not admin_token:
            logger.warning("[SecurityConfig] FEEDBACK_ADMIN_TOKEN not set")

        if errors:
            for error in errors:
                logger.error("[SecurityConfig] %s", error)
            raise ValueError(
                f"Security configuration errors: {'; '.join(errors)}"
            )

        logger.info("[SecurityConfig] Validation passed")
        return True

    @classmethod
    def get_header(cls, name: str) -> Optional[str]:
        """
        Get security header value.
        
        Args:
            name: Header name
            
        Returns:
            Header value or None
        """
        return cls.SECURITY_HEADERS.get(name)

    @classmethod
    def all_headers(cls) -> dict:
        """Get all security headers."""
        return cls.SECURITY_HEADERS.copy()
