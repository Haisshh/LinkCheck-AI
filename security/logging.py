"""Secure logging with sensitive data filtering."""

import logging
import re
from typing import Optional

logger = logging.getLogger("linkcheck.security.logging")


class SensitiveDataFilter(logging.Filter):
    """Remove sensitive data from logs."""

    SENSITIVE_PATTERNS = [
        (r"VIRUSTOTAL_API_KEY\s*=\s*[^\s,\n]+", "VIRUSTOTAL_API_KEY=***"),
        (r"GOOGLE_SAFE_BROWSING_API_KEY\s*=\s*[^\s,\n]+", "GOOGLE_SAFE_BROWSING_API_KEY=***"),
        (r"IPQS_API_KEY\s*=\s*[^\s,\n]+", "IPQS_API_KEY=***"),
        (r"PHISHTANK_API_KEY\s*=\s*[^\s,\n]+", "PHISHTANK_API_KEY=***"),
        (r"URLHAUS_AUTH_KEY\s*=\s*[^\s,\n]+", "URLHAUS_AUTH_KEY=***"),
        (r"FEEDBACK_ADMIN_TOKEN\s*=\s*[^\s,\n]+", "FEEDBACK_ADMIN_TOKEN=***"),
        (r"SECRET_KEY\s*=\s*[^\s,\n]+", "SECRET_KEY=***"),
        (r"Bearer\s+[^\s]+", "Bearer ***"),
        (r"Authorization:\s*[^\s]+", "Authorization: ***"),
        (r"x-apikey:\s*[^\s]+", "x-apikey: ***"),
        (r"Authorization['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", "Authorization=***"),
        (r"password['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", "password=***"),
        (r"token['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", "token=***"),
    ]

    @staticmethod
    def filter(record: logging.LogRecord) -> bool:
        """
        Filter log record and remove sensitive data.

        Args:
            record: Log record to filter

        Returns:
            True to allow record to be logged
        """
        if not record.msg:
            return True

        msg = str(record.msg)

        for pattern, replacement in SensitiveDataFilter.SENSITIVE_PATTERNS:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)

        record.msg = msg

        if record.args:
            try:
                for i, arg in enumerate(record.args):
                    if isinstance(arg, str):
                        for pattern, replacement in SensitiveDataFilter.SENSITIVE_PATTERNS:
                            arg = re.sub(pattern, replacement, arg, flags=re.IGNORECASE)
                        record.args = tuple(
                            arg if j == i else record.args[j]
                            for j in range(len(record.args))
                        )
            except Exception:
                pass

        return True


class RequestLogger:
    """Log security-relevant requests."""

    @staticmethod
    def log_auth_attempt(
        client_id: str,
        username: Optional[str] = None,
        success: bool = False,
        reason: Optional[str] = None,
    ) -> None:
        """
        Log authentication attempt.

        Args:
            client_id: Client IP/identifier
            username: Username (if applicable)
            success: Whether authentication succeeded
            reason: Failure reason if applicable
        """
        status = "SUCCESS" if success else "FAILED"
        username_str = f" user={username}" if username else ""
        reason_str = f" ({reason})" if reason else ""
        logger.warning("[AUTH] %s from %s%s%s", status, client_id, username_str, reason_str)

    @staticmethod
    def log_rate_limit_violation(
        client_id: str,
        endpoint: str,
        violation_type: str,
    ) -> None:
        """
        Log rate limit violation.

        Args:
            client_id: Client identifier
            endpoint: API endpoint
            violation_type: Type of violation
        """
        logger.warning("[RATE_LIMIT] %s from %s on %s", violation_type, client_id, endpoint)

    @staticmethod
    def log_security_event(
        event_type: str,
        details: Optional[str] = None,
        severity: str = "INFO",
    ) -> None:
        """
        Log security event.

        Args:
            event_type: Type of security event
            details: Event details
            severity: Event severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        details_str = f": {details}" if details else ""
        log_func = getattr(logger, severity.lower(), logger.info)
        log_func("[SECURITY] %s%s", event_type, details_str)

    @staticmethod
    def log_invalid_input(
        client_id: str,
        endpoint: str,
        reason: str,
    ) -> None:
        """
        Log invalid input attempt.

        Args:
            client_id: Client identifier
            endpoint: API endpoint
            reason: Why input was invalid
        """
        logger.warning("[INVALID_INPUT] %s on %s: %s", client_id, endpoint, reason)

    @staticmethod
    def log_unauthorized_access(
        client_id: str,
        resource: str,
        reason: str,
    ) -> None:
        """
        Log unauthorized access attempt.

        Args:
            client_id: Client identifier
            resource: Resource being accessed
            reason: Why access was denied
        """
        logger.warning("[UNAUTHORIZED] %s tried to access %s: %s", client_id, resource, reason)


def setup_secure_logging(app=None) -> None:
    """
    Setup secure logging with sensitive data filtering.

    Args:
        app: Flask application instance (optional)
    """
    root_logger = logging.getLogger()

    filter_obj = SensitiveDataFilter()
    for handler in root_logger.handlers:
        handler.addFilter(filter_obj)

    if app:
        app.logger.addFilter(filter_obj)

    logger.info("[SecureLogging] Initialized with sensitive data filter")
