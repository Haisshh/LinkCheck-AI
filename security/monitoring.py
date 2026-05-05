"""Security monitoring and vulnerability scanning."""

import logging
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("linkcheck.security.monitoring")


class SecurityMonitor:
    """Monitor security events and detect anomalies."""

    def __init__(self):
        """Initialize security monitor."""
        self.failed_auth_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.rate_limit_violations: Dict[str, List[datetime]] = defaultdict(list)
        self.invalid_inputs: Dict[str, List[datetime]] = defaultdict(list)
        self.unauthorized_accesses: Dict[str, List[datetime]] = defaultdict(list)

    def record_failed_auth(self, client_id: str, retain_minutes: int = 60) -> None:
        """
        Record failed authentication attempt.

        Args:
            client_id: Client identifier
            retain_minutes: How long to retain records
        """
        now = datetime.utcnow()
        self.failed_auth_attempts[client_id].append(now)

        # Cleanup old records
        cutoff = now - timedelta(minutes=retain_minutes)
        self.failed_auth_attempts[client_id] = [
            t for t in self.failed_auth_attempts[client_id] if t > cutoff
        ]

    def record_rate_limit_violation(
        self,
        client_id: str,
        retain_minutes: int = 60,
    ) -> None:
        """
        Record rate limit violation.

        Args:
            client_id: Client identifier
            retain_minutes: How long to retain records
        """
        now = datetime.utcnow()
        self.rate_limit_violations[client_id].append(now)

        # Cleanup old records
        cutoff = now - timedelta(minutes=retain_minutes)
        self.rate_limit_violations[client_id] = [
            t for t in self.rate_limit_violations[client_id] if t > cutoff
        ]

    def record_invalid_input(
        self,
        client_id: str,
        retain_minutes: int = 60,
    ) -> None:
        """
        Record invalid input attempt.

        Args:
            client_id: Client identifier
            retain_minutes: How long to retain records
        """
        now = datetime.utcnow()
        self.invalid_inputs[client_id].append(now)

        # Cleanup old records
        cutoff = now - timedelta(minutes=retain_minutes)
        self.invalid_inputs[client_id] = [
            t for t in self.invalid_inputs[client_id] if t > cutoff
        ]

    def get_failed_auth_count(self, client_id: str, minutes: int = 10) -> int:
        """
        Get number of failed auth attempts in last N minutes.

        Args:
            client_id: Client identifier
            minutes: Time window in minutes

        Returns:
            Count of failed attempts
        """
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return sum(
            1 for t in self.failed_auth_attempts[client_id] if t > cutoff
        )

    def should_block_client(self, client_id: str, max_failures: int = 5) -> bool:
        """
        Check if client should be blocked based on failed attempts.

        Args:
            client_id: Client identifier
            max_failures: Maximum allowed failures

        Returns:
            True if client should be blocked
        """
        return self.get_failed_auth_count(client_id) >= max_failures


class VulnerabilityScanner:
    """Scan for security vulnerabilities in configuration."""

    VULNERABILITIES: List[Tuple[str, callable]] = []

    @staticmethod
    def check_secret_key() -> Tuple[bool, Optional[str]]:
        """
        Check if SECRET_KEY is properly configured.

        Returns:
            Tuple of (is_secure, vulnerability_description)
        """
        secret_key = os.environ.get("SECRET_KEY", "")

        if not secret_key:
            return False, "SECRET_KEY not set"

        if secret_key == "dev-only-change-me":
            return False, "SECRET_KEY using default development value"

        if len(secret_key) < 32:
            return False, f"SECRET_KEY too short ({len(secret_key)} chars, minimum 32)"

        return True, None

    @staticmethod
    def check_debug_mode() -> Tuple[bool, Optional[str]]:
        """
        Check if debug mode is disabled in production.

        Returns:
            Tuple of (is_secure, vulnerability_description)
        """
        flask_debug = os.environ.get("FLASK_DEBUG", "false").lower()

        if flask_debug == "true":
            return False, "FLASK_DEBUG enabled in production"

        return True, None

    @staticmethod
    def check_environment() -> Tuple[bool, Optional[str]]:
        """
        Check if environment is set to production.

        Returns:
            Tuple of (is_secure, vulnerability_description)
        """
        flask_env = os.environ.get("FLASK_ENV", "production")

        if flask_env != "production":
            return False, f"FLASK_ENV set to {flask_env} (not production)"

        return True, None

    @staticmethod
    def check_admin_token() -> Tuple[bool, Optional[str]]:
        """
        Check if admin token is configured.

        Returns:
            Tuple of (is_configured, vulnerability_description)
        """
        admin_token = os.environ.get("FEEDBACK_ADMIN_TOKEN", "")

        if not admin_token:
            return False, "FEEDBACK_ADMIN_TOKEN not configured"

        if len(admin_token) < 16:
            return False, f"FEEDBACK_ADMIN_TOKEN too short ({len(admin_token)} chars, minimum 16)"

        return True, None

    @staticmethod
    def run_all_checks() -> Dict[str, Tuple[bool, Optional[str]]]:
        """
        Run all vulnerability checks.

        Returns:
            Dictionary of check results
        """
        checks = {
            "secret_key": VulnerabilityScanner.check_secret_key(),
            "debug_mode": VulnerabilityScanner.check_debug_mode(),
            "environment": VulnerabilityScanner.check_environment(),
            "admin_token": VulnerabilityScanner.check_admin_token(),
        }

        return checks

    @staticmethod
    def log_vulnerabilities() -> int:
        """
        Run all checks and log vulnerabilities.

        Returns:
            Number of vulnerabilities found
        """
        checks = VulnerabilityScanner.run_all_checks()
        vulnerabilities = 0

        for check_name, (is_secure, error) in checks.items():
            if not is_secure:
                vulnerabilities += 1
                logger.error("[VulnerabilityScanner] %s: %s", check_name, error)
            else:
                logger.info("[VulnerabilityScanner] %s: OK", check_name)

        return vulnerabilities
