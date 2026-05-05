"""Security decorators for Flask routes."""

import logging
from functools import wraps
from typing import Optional, Callable

from flask import request, jsonify, abort

from security.validators import InputValidator, ResponseValidator
from security.auth import AuthValidator, TokenManager
from security.logging import RequestLogger

logger = logging.getLogger("linkcheck.security.decorators")


def validate_json_payload(required_fields: Optional[list] = None) -> Callable:
    """
    Decorator to validate JSON payload.

    Args:
        required_fields: List of required field names

    Returns:
        Decorated function
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = ResponseValidator.extract_client_ip(request)

            # Validate Content-Type
            is_valid, error = ResponseValidator.validate_content_type(request)
            if not is_valid:
                RequestLogger.log_invalid_input(client_id, request.path, error)
                return jsonify({"error": error, "code": "INVALID_CONTENT_TYPE"}), 400

            # Get JSON data
            try:
                data = request.get_json(silent=True)
                if data is None:
                    data = {}
            except Exception as e:
                RequestLogger.log_invalid_input(client_id, request.path, f"JSON parse error: {e}")
                return jsonify({"error": "Invalid JSON", "code": "INVALID_JSON"}), 400

            # Validate required fields
            if required_fields:
                missing = [f for f in required_fields if f not in data]
                if missing:
                    error_msg = f"Missing required fields: {', '.join(missing)}"
                    RequestLogger.log_invalid_input(client_id, request.path, error_msg)
                    return jsonify({"error": error_msg, "code": "MISSING_FIELDS"}), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def validate_url_input(field_name: str = "url") -> Callable:
    """
    Decorator to validate URL input.

    Args:
        field_name: JSON field name containing URL

    Returns:
        Decorated function
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = ResponseValidator.extract_client_ip(request)
            data = request.get_json(silent=True) or {}
            url = str(data.get(field_name, "")).strip()

            if not url:
                RequestLogger.log_invalid_input(client_id, request.path, "URL missing or empty")
                return jsonify({"error": "Missing URL", "code": "MISSING_URL"}), 400

            is_valid, error = InputValidator.validate_url(url)
            if not is_valid:
                RequestLogger.log_invalid_input(client_id, request.path, f"Invalid URL: {error}")
                return jsonify({"error": error, "code": "INVALID_URL"}), 400

            is_suspicious, pattern = InputValidator.is_suspicious(url)
            if is_suspicious:
                RequestLogger.log_invalid_input(client_id, request.path, f"Suspicious URL pattern: {pattern}")
                return jsonify({"error": "URL contains suspicious patterns", "code": "SUSPICIOUS_URL"}), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def sanitize_request_data() -> Callable:
    """
    Decorator to sanitize request data.

    Returns:
        Decorated function
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = ResponseValidator.extract_client_ip(request)
            data = request.get_json(silent=True) or {}

            # Check for suspicious patterns in all string values
            for key, value in data.items():
                if isinstance(value, str):
                    is_suspicious, pattern = InputValidator.is_suspicious(value)
                    if is_suspicious:
                        RequestLogger.log_invalid_input(
                            client_id,
                            request.path,
                            f"Suspicious pattern in {key}: {pattern}",
                        )
                        return jsonify(
                            {"error": "Request contains suspicious data", "code": "SUSPICIOUS_DATA"}
                        ), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_auth_token(token_source: str = "header") -> Callable:
    """
    Decorator to require authentication token.

    Args:
        token_source: Where to get token ("header" or "query")

    Returns:
        Decorated function
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = ResponseValidator.extract_client_ip(request)
            token = None

            # Extract token from header
            if token_source == "header":
                auth_header = request.headers.get("Authorization", "")
                token = AuthValidator.extract_token_from_header(auth_header)
                if not token:
                    RequestLogger.log_unauthorized_access(
                        client_id,
                        request.path,
                        "Missing or invalid Authorization header",
                    )
                    return jsonify({"error": "Unauthorized", "code": "MISSING_AUTH"}), 401

            # Extract token from query parameter
            elif token_source == "query":
                token = request.args.get("token", "").strip()
                if not token:
                    RequestLogger.log_unauthorized_access(
                        client_id,
                        request.path,
                        "Missing token query parameter",
                    )
                    return jsonify({"error": "Unauthorized", "code": "MISSING_TOKEN"}), 401

            # Validate token
            is_valid, error = AuthValidator.validate_admin_token(token)
            if not is_valid:
                RequestLogger.log_unauthorized_access(client_id, request.path, error)
                return jsonify({"error": "Unauthorized", "code": "INVALID_TOKEN"}), 401

            return f(*args, **kwargs)

        return decorated_function

    return decorator
