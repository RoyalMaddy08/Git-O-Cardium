"""Minimal MiniMoth client (https://minimoth.dev), standard library only.

Endpoints and error codes follow https://minimoth.dev/llms-full.txt. The API key is read from the
MINIMOTH_API_KEY environment variable and is never written to disk, logs or the UI.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

DEFAULT_BASE = "https://api.minimoth.dev"


class MiniMothError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 0, request_id: str = ""):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status, self.request_id = code, message, status, request_id


def normalize_phone(raw: str) -> str:
    """Indian mobile numbers only for this project. Returns +91XXXXXXXXXX."""
    p = re.sub(r"[\s\-()]", "", raw or "")
    if re.fullmatch(r"[6-9]\d{9}", p):
        p = "+91" + p
    if not re.fullmatch(r"\+91[6-9]\d{9}", p):
        raise ValueError("enter an Indian mobile number such as +919876543210")
    return p


def mask_phone(p: str) -> str:
    return p[:3] + "*" * max(0, len(p) - 7) + p[-4:] if p and len(p) > 7 else "your phone"


class MiniMoth:
    def __init__(self, api_key: str, base_url: str | None = None, timeout: float = 10.0):
        self._key = api_key
        self.base = (base_url or os.environ.get("MINIMOTH_BASE_URL") or DEFAULT_BASE).rstrip("/")
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "MiniMoth | None":
        key = os.environ.get("MINIMOTH_API_KEY", "").strip()
        return cls(key) if key else None

    @property
    def is_test_key(self) -> bool:
        return self._key.startswith("mm_test_")

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.base + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"X-Api-Key": self._key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode() or "{}"
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            try:
                d = json.loads(e.read().decode())
            except ValueError:
                d = {}
            raise MiniMothError(d.get("code", "HTTP_ERROR"), d.get("error", ""), e.code, d.get("request_id", "")) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise MiniMothError("NETWORK_ERROR", str(e)) from None

    def send_otp(self, phone: str) -> dict:
        return self._call("POST", "/v1/otp/send", {"phone": phone})

    def verify_otp(self, phone: str, code: str) -> dict:
        return self._call("POST", "/v1/otp/verify", {"phone": phone, "code": code})

    def validate(self, access_token: str) -> dict:
        return self._call("POST", "/v1/session/validate", {"access_token": access_token})

    def refresh(self, refresh_token: str) -> dict:
        return self._call("POST", "/v1/session/refresh", {"refresh_token": refresh_token})

    def logout(self, access_token: str) -> None:
        self._call("POST", "/v1/session/logout", {"access_token": access_token})
