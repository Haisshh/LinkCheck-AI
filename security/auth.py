"""Authentication and authorization utilities."""

import os
import secrets
import hmac
import hashlib
import logging
from typing import Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger("linkcheck.security.auth")


class TokenManager:
    """Manage authentication tokens securely."""

    TOKEN_LENGTH = 32  # bytes
    TOKEN_EXPIRY_HOURS = 24

    @staticmethod
    def generate_token() -> str:
        """
        Generate a cryptographically secure random token.

        Returns:
            URL-safe token string
        """
        return secrets.token_urlsafe(TokenManager.TOKEN_LENGTH)

    @staticmethod
    def hash_token(token: str, secret: Optional[str] = None) -> str:
        """
        Hash a token using HMAC-SHA256.

        Args:
            token: Token to hash
            secret: Secret key (defaults to SECRET_KEY env var)

        Returns:
            Hashed token (hex string)
        """
        if secret is None:
            secret = os.environ.get("SECRET_KEY", "default-secret")

        return hmac.new(
            secret.encode(),
            token.encode(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_token(token: str, token_hash: str, secret: Optional[str] = None) -> bool:
        """
        Verify a token against its hash (timing-safe comparison).

        Args:
            token: Token to verify
            token_hash: Expected hash
            secret: Secret key (defaults to SECRET_KEY env var)

        Returns:
            True if token matches hash
        """
        computed_hash = TokenManager.hash_token(token, secret)
        return hmac.compare_digest(computed_hash, token_hash)

    @staticmethod
    def generate_expiry(hours: Optional[int] = None) -> datetime:
        """
        Generate token expiry timestamp.

        Args:
            hours: Hours from now (defaults to TOKEN_EXPIRY_HOURS)

        Returns:
            Expiry datetime
        """
        if hours is None:
            hours = TokenManager.TOKEN_EXPIRY_HOURS
        return datetime.utcnow() + timedelta(hours=hours)

    @staticmethod
    def is_expired(expiry: datetime) -> bool:
        """
        Check if token is expired.

        Args:
            expiry: Expiry datetime

        Returns:
            True if expired
        """
        return datetime.utcnow() > expiry


class AuthValidator:
    """Validate authentication credentials and tokens."""

    @staticmethod
    def validate_token_format(token: str) -> Tuple[bool, Optional[str]]:
        """
        Validate token format.

        Args:
            token: Token to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not token:
            return False, "Token is empty"

        if len(token) < 16:
            return False, "Token too short"

        if len(token) > 256:
            return False, "Token too long"

        # Check for valid URL-safe base64 characters
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        if not all(c in valid_chars for c in token):
            return False, "Token contains invalid characters"

        return True, None

    @staticmethod
    def validate_authorization_header(auth_header: str) -> Tuple[bool, Optional[str]]:
        """
        Validate Authorization header format.

        Args:
            auth_header: Authorization header value

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not auth_header:
            return False, "Authorization header missing"

        parts = auth_header.split(" ")
        if len(parts) != 2:
            return False, "Invalid Authorization header format"

        scheme, token = parts
        if scheme.lower() != "bearer":
            return False, f"Invalid auth scheme: {scheme}"

        return AuthValidator.validate_token_format(token)

    @staticmethod
    def extract_token_from_header(auth_header: str) -> Optional[str]:
        """
        Extract token from Authorization header.

        Args:
            auth_header: Authorization header value

        Returns:
            Token string or None
        """
        is_valid, _ = AuthValidator.validate_authorization_header(auth_header)
        if not is_valid:
            return None

        return auth_header.split(" ")[1]

    @staticmethod
    def validate_admin_token(token: str, expected_token: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate admin token using timing-safe comparison.

        Args:
            token: Token to verify
            expected_token: Expected token (defaults to FEEDBACK_ADMIN_TOKEN env var)

        Returns:
            Tuple of (is_valid, error_message)
        """
        if expected_token is None:
            expected_token = os.environ.get("FEEDBACK_ADMIN_TOKEN", "")

        if not expected_token:
            return False, "Admin token not configured"

        # Always compare full strings to prevent timing attacks
        if hmac.compare_digest(token, expected_token):
            return True, None

        logger.warning("[Auth] Invalid admin token attempt")
        return False, "Invalid token"
