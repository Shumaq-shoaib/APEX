"""
AuthEngine — Automated Token Acquisition for APEX Dynamic Scanning.

Discovers login endpoints from the OpenAPI blueprint, authenticates using
provided credentials, and extracts the resulting JWT/Bearer token.
"""
import httpx
import json
import re
from typing import Optional
from app.core.logging import get_logger

logger = get_logger(__name__)

# ─── Heuristic Constants ───────────────────────────────────────────────
LOGIN_PATH_KEYWORDS = ["login", "signin", "sign-in", "auth", "authenticate", "token", "oauth"]
TOKEN_RESPONSE_KEYS = ["auth_token", "access_token", "token", "jwt", "id_token", "bearer"]


class AuthEngineError(Exception):
    """Raised when automated authentication fails."""
    pass


class AuthEngine:
    """
    Smart authentication engine that:
    1. Discovers the login endpoint from the OpenAPI blueprint.
    2. Sends a POST request with user-provided credentials.
    3. Heuristically extracts the JWT/Bearer token from the response.
    """

    def __init__(self, target_url: str, blueprint: dict):
        self.target_url = target_url.rstrip("/")
        self.blueprint = blueprint or {}

    # ─── Public API ────────────────────────────────────────────────────

    def fetch_token(
        self,
        username: str,
        password: str,
        login_endpoint: Optional[str] = None,
        username_field: str = "username",
        token_path: Optional[str] = None,
    ) -> str:
        """
        Authenticate and return a raw token string (no 'Bearer ' prefix).

        Args:
            username:        The username or email to log in with.
            password:        The password.
            login_endpoint:  (Override) Explicit path like '/users/v1/login'.
            username_field:  (Override) JSON key for username, e.g. 'email'.
            token_path:      (Override) Dot-separated path like 'data.jwt'.

        Returns:
            The raw token string.

        Raises:
            AuthEngineError on any failure.
        """
        # 1. Discover or use provided endpoint
        endpoint = login_endpoint or self._find_login_endpoint()
        if not endpoint:
            raise AuthEngineError(
                "Could not discover a login endpoint from the API spec. "
                "Please provide it manually via 'Login Endpoint' in Advanced Settings."
            )

        url = f"{self.target_url}{endpoint}"
        payload = {username_field: username, "password": password}

        logger.info(
            "AuthEngine: Attempting login",
            event="auth_login_attempt",
            url=url,
            username_field=username_field,
        )

        # 2. Send the login request
        try:
            with httpx.Client(timeout=15.0, verify=False) as client:
                response = client.post(url, json=payload)
        except httpx.ConnectError as e:
            raise AuthEngineError(f"Could not connect to login endpoint {url}: {e}")
        except httpx.TimeoutException:
            raise AuthEngineError(f"Login request to {url} timed out.")
        except Exception as e:
            raise AuthEngineError(f"Unexpected error during login request: {e}")

        if response.status_code >= 400:
            raise AuthEngineError(
                f"Login failed with HTTP {response.status_code}. "
                f"Response: {response.text[:500]}"
            )

        # 3. Extract the token
        try:
            response_data = response.json()
        except Exception:
            raise AuthEngineError(
                f"Login endpoint returned non-JSON response: {response.text[:300]}"
            )

        # 3b. Detect soft failures (APIs that return HTTP 200 with failure body)
        status_field = response_data.get("status", "").lower()
        if status_field in ("fail", "error", "failure", "denied", "unauthorized"):
            msg = response_data.get("message", response_data.get("error", "Unknown error"))
            raise AuthEngineError(
                f"Login failed (API returned success HTTP but failure body): {msg}"
            )

        token = self._extract_token(response_data, custom_path=token_path)
        if not token:
            raise AuthEngineError(
                f"Could not locate a token in the login response. "
                f"Keys found: {list(response_data.keys())}. "
                f"Please set 'Token Path' in Advanced Settings."
            )

        # Strip any accidental whitespace/newlines (the original bug!)
        token = token.strip()

        logger.info(
            "AuthEngine: Login successful",
            event="auth_login_success",
            url=url,
            token_length=len(token),
        )
        return token

    # ─── Heuristics ────────────────────────────────────────────────────

    def _find_login_endpoint(self) -> Optional[str]:
        """
        Search the blueprint endpoints for paths that look like a login endpoint.
        Prioritizes POST methods and paths containing login-related keywords.
        """
        endpoints = self.blueprint.get("endpoints", [])
        candidates = []

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()

            # Normalize paths like "POST /users/v1/login" (space-separated)
            if " " in path:
                parts = path.split(" ", 1)
                method = parts[0].upper()
                path = parts[1]

            path_lower = path.lower()

            for keyword in LOGIN_PATH_KEYWORDS:
                if keyword in path_lower:
                    # Score: POST is strongly preferred
                    score = 10 if method == "POST" else 1
                    # Exact segment match scores higher than partial
                    segments = path_lower.split("/")
                    if keyword in segments:
                        score += 5
                    candidates.append((score, path))
                    break

        if not candidates:
            return None

        # Return the highest-scoring candidate
        candidates.sort(key=lambda x: x[0], reverse=True)
        best = candidates[0][1]
        logger.info(f"AuthEngine: Discovered login endpoint: {best}")
        return best

    def _extract_token(self, response_data: dict, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Extract a token from the login response body.

        Strategy:
        1. If a custom_path is supplied (e.g. 'data.jwt'), navigate to it directly.
        2. Otherwise, recursively search for keys that match TOKEN_RESPONSE_KEYS.
        """
        # Custom path override
        if custom_path:
            return self._navigate_path(response_data, custom_path)

        # Heuristic: flat search for known keys
        token = self._search_keys(response_data)
        return token

    @staticmethod
    def _navigate_path(data: dict, dot_path: str) -> Optional[str]:
        """Navigate a dot-separated path like 'data.access_token' into a nested dict."""
        keys = dot_path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return str(current) if current is not None else None

    def _search_keys(self, data, depth: int = 0) -> Optional[str]:
        """Recursively search for token-like keys up to 3 levels deep."""
        if depth > 3 or not isinstance(data, dict):
            return None

        for key in TOKEN_RESPONSE_KEYS:
            if key in data and isinstance(data[key], str) and len(data[key]) > 10:
                return data[key]

        # Search nested dicts
        for value in data.values():
            if isinstance(value, dict):
                result = self._search_keys(value, depth + 1)
                if result:
                    return result

        return None
