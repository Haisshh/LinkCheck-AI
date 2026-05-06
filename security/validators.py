"""Input and output validation."""

import re
import logging
from typing import Optional, Tuple, Any, Dict
from urllib.parse import urlparse

logger = logging.getLogger("linkcheck.security.validators")


class InputValidator:
    """Validate user inputs."""

    # URL patterns
    URL_PATTERN = re.compile(
        r"^https?://([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}.*$"
    )

    # Hostname pattern (RFC 1123)
    HOSTNAME_PATTERN = re.compile(
        r"^(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)*([a-zA-Z]{2,63})$"
    )

    # IP address pattern (basic)
    IP_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    SUSPICIOUS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onclick=",
        r"eval\(",
        r"exec\(",
        r"shell_exec",
        r"system\(",
        r"__.*__",  # Python magic methods
        r"\$\{.*\}",  # Template injection
    ]

    @staticmethod
    def validate_url(url: str, max_length: int = 2048) -> Tuple[bool, Optional[str]]:
        """
        Validate URL format and length.

        Args:
            url: URL to validate
            max_length: Maximum URL length

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL is empty"

        if len(url) > max_length:
            return False, f"URL exceeds maximum length ({max_length} chars)"

        # Add scheme if missing
        test_url = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(test_url)
            if not parsed.netloc:
                return False, "Invalid URL: missing hostname"
            if parsed.scheme not in ("http", "https"):
                return False, f"Invalid URL scheme: {parsed.scheme}"
        except Exception as e:
            return False, f"URL parsing failed: {str(e)}"

        return True, None

    @staticmethod
    def validate_hostname(hostname: str, max_length: int = 255) -> Tuple[bool, Optional[str]]:
        """
        Validate hostname format.

        Args:
            hostname: Hostname to validate
            max_length: Maximum hostname length

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not hostname:
            return False, "Hostname is empty"

        if len(hostname) > max_length:
            return False, f"Hostname exceeds maximum length ({max_length} chars)"

        hostname_clean = hostname.lower().strip()

        # Check if it's an IP address
        if InputValidator.IP_PATTERN.match(hostname_clean):
            return True, None

        # Check hostname pattern
        if InputValidator.HOSTNAME_PATTERN.match(hostname_clean):
            return True, None

        return False, "Invalid hostname format"

    @staticmethod
    def validate_string(
        value: str,
        min_length: int = 1,
        max_length: int = 1000,
        allow_special: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate string input.

        Args:
            value: String to validate
            min_length: Minimum length
            max_length: Maximum length
            allow_special: Allow special characters

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(value, str):
            return False, "Value must be a string"

        if len(value) < min_length:
            return False, f"String too short (minimum {min_length} chars)"

        if len(value) > max_length:
            return False, f"String too long (maximum {max_length} chars)"

        if not allow_special:
            if not value.replace(" ", "").replace("-", "").isalnum():
                return False, "String contains invalid characters"

        return True, None

    @staticmethod
    def is_suspicious(value: str) -> Tuple[bool, Optional[str]]:
        """
        Check if string contains suspicious patterns.

        Args:
            value: String to check

        Returns:
            Tuple of (is_suspicious, matched_pattern)
        """
        value_lower = value.lower()
        for pattern in InputValidator.SUSPICIOUS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True, pattern
        return False, None


class ResponseValidator:
    """Validate and sanitize responses."""

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    @staticmethod
    def add_security_headers(response: Any) -> None:
        """
        Add security headers to response.

        Args:
            response: Flask response object
        """
        for header, value in ResponseValidator.SECURITY_HEADERS.items():
            response.headers[header] = value

    @staticmethod
    def set_no_cache(response: Any) -> None:
        """
        Set no-cache headers on response.

        Args:
            response: Flask response object
        """
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    @staticmethod
    def validate_json_response(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate JSON response structure.

        Args:
            data: Dictionary to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(data, dict):
            return False, "Response must be a dictionary"

        if len(str(data)) > 10_000_000:  # 10 MB
            return False, "Response too large"

        return True, None

    @staticmethod
    def extract_client_ip(request: Any) -> str:
        """
        Safely extract client IP from Flask request.

        Args:
            request: Flask request object

        Returns:
            Client IP address
        """
        # Check X-Forwarded-For (for proxies)
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP", "")
        if real_ip:
            return real_ip.strip()

        # Fallback to remote_addr
        return request.remote_addr or "unknown"

    @staticmethod
    def validate_content_type(request: Any, expected: str = "application/json") -> Tuple[bool, Optional[str]]:
        """
        Validate Content-Type header.

        Args:
            request: Flask request object
            expected: Expected Content-Type

        Returns:
            Tuple of (is_valid, error_message)
        """
        content_type = request.headers.get("Content-Type", "")
        if not content_type:
            return False, "Content-Type header missing"

        if expected.lower() not in content_type.lower():
            return False, f"Invalid Content-Type: {content_type}"

        return True, None
