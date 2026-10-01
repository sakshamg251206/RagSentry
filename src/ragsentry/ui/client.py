"""Small HTTP client the dashboard uses to talk to the RagSentry API."""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_API_URL = "http://127.0.0.1:8000"


class ApiError(Exception):
    """A request to the API failed. `message` is safe to show to end users."""

    def __init__(self, message: str, status_code: int | None = None, detail: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail


class RagSentryClient:
    def __init__(self, base_url: str | None = None, timeout: float = 120.0) -> None:
        self.base_url = (base_url or os.getenv("RAGSENTRY_API_URL") or DEFAULT_API_URL).rstrip("/")
        self._timeout = timeout

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            with httpx.Client(base_url=self.base_url, timeout=self._timeout) as http:
                resp = http.request(method, path, **kwargs)
        except httpx.ConnectError as exc:
            raise ApiError(f"Cannot reach the RagSentry API at {self.base_url}.") from exc
        except httpx.TimeoutException as exc:
            raise ApiError("The API took too long to respond. Try again.") from exc
        except httpx.HTTPError as exc:
            raise ApiError(f"Network error: {exc}") from exc

        if resp.is_success:
            return resp.json()
        raise ApiError(_error_message(resp), resp.status_code, _detail(resp))

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/api/health", timeout=5.0)  # type: ignore[no-any-return]

    def query_target(self, prompt: str) -> dict[str, Any]:
        return self._request("POST", "/api/target/query", json={"prompt": prompt})  # type: ignore[no-any-return]

    def start_audit(self) -> dict[str, Any]:
        return self._request("POST", "/api/audits")  # type: ignore[no-any-return]

    def get_audit(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/audits/{job_id}", timeout=10.0)  # type: ignore[no-any-return]


def _detail(resp: httpx.Response) -> Any:
    try:
        body = resp.json()
    except ValueError:
        return None
    return body.get("detail") if isinstance(body, dict) else None


def _error_message(resp: httpx.Response) -> str:
    detail = _detail(resp)
    if isinstance(detail, dict):
        return str(detail.get("message", detail))
    if isinstance(detail, list) and detail:  # FastAPI validation errors
        return str(detail[0].get("msg", detail))
    return str(detail or f"API error {resp.status_code}.")
