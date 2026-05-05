"""Encryption and hashing utilities."""

import os
import hashlib
import hmac
import secrets
import logging
from typing import Optional

try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

logger = logging.getLogger("linkcheck.security.encryption")


class EncryptionManager:
    """Manage symmetric encryption with Fernet."""

    def __init__(self, key: Optional[str] = None):
        """
        Initialize encryption manager.

        Args:
            key: Encryption key (defaults to ENCRYPTION_KEY env var)
        """
        if not ENCRYPTION_AVAILABLE:
            raise ImportError("cryptography library required for encryption")

        if key is None:
            key = os.environ.get("ENCRYPTION_KEY", "")

        if not key:
            # Generate new key if not provided
            key = Fernet.generate_key().decode()
            logger.warning("[EncryptionManager] Generated new encryption key")

        try:
            # Ensure key is valid base64
            self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
            self.key = key
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string.

        Args:
            plaintext: String to encrypt

        Returns:
            Encrypted string (base64-encoded)
        """
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")

        ciphertext = self.cipher.encrypt(plaintext.encode())
        return ciphertext.decode()

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext string.

        Args:
            ciphertext: Encrypted string (base64-encoded)

        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            raise ValueError("Ciphertext cannot be empty")

        try:
            plaintext = self.cipher.decrypt(ciphertext.encode())
            return plaintext.decode()
        except Exception as e:
            logger.error("[EncryptionManager] Decryption failed: %s", e)
            raise ValueError(f"Decryption failed: {e}")


class PasswordManager:
    """Manage password hashing and verification."""

    ALGORITHM = "sha256"
    ITERATIONS = 100000  # PBKDF2
    SALT_LENGTH = 32

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> tuple:
        """
        Hash password using PBKDF2-SHA256.

        Args:
            password: Plain text password
            salt: Salt bytes (generated if not provided)

        Returns:
            Tuple of (hashed_password, salt) both as hex strings
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        if salt is None:
            salt = secrets.token_bytes(PasswordManager.SALT_LENGTH)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)

        hashed = hashlib.pbkdf2_hmac(
            PasswordManager.ALGORITHM,
            password.encode(),
            salt,
            PasswordManager.ITERATIONS,
        )

        return hashed.hex(), salt.hex()

    @staticmethod
    def verify_password(password: str, password_hash: str, salt: str) -> bool:
        """
        Verify password against hash using timing-safe comparison.

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash (hex string)
            salt: Stored salt (hex string)

        Returns:
            True if password matches
        """
        try:
            computed_hash, _ = PasswordManager.hash_password(password, salt)
            return hmac.compare_digest(computed_hash, password_hash)
        except Exception as e:
            logger.error("[PasswordManager] Verification failed: %s", e)
            return False

    @staticmethod
    def validate_password_strength(password: str) -> tuple:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password cannot be empty"

        if len(password) < 12:
            return False, "Password must be at least 12 characters"

        if len(password) > 128:
            return False, "Password is too long"

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if not (has_upper and has_lower and has_digit):
            return False, "Password must include uppercase, lowercase, and digits"

        return True, None


class HashManager:
    """Manage secure hashing."""

    @staticmethod
    def hash_sha256(data: str) -> str:
        """
        Hash data using SHA256.

        Args:
            data: Data to hash

        Returns:
            Hex digest
        """
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_sha512(data: str) -> str:
        """
        Hash data using SHA512.

        Args:
            data: Data to hash

        Returns:
            Hex digest
        """
        return hashlib.sha512(data.encode()).hexdigest()

    @staticmethod
    def hmac_sha256(data: str, key: str) -> str:
        """
        Generate HMAC-SHA256.

        Args:
            data: Data to hash
            key: Secret key

        Returns:
            Hex digest
        """
        return hmac.new(
            key.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_hmac_sha256(data: str, signature: str, key: str) -> bool:
        """
        Verify HMAC-SHA256 using timing-safe comparison.

        Args:
            data: Original data
            signature: HMAC signature to verify
            key: Secret key

        Returns:
            True if signature is valid
        """
        computed = HashManager.hmac_sha256(data, key)
        return hmac.compare_digest(computed, signature)
