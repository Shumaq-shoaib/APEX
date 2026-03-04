"""
HTTP utility functions for scanners.
"""
import httpx
import logging
import time
import json as json_lib
from dataclasses import dataclass, field
from typing import Dict, Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class RequestRecord:
    """Captures the full HTTP exchange for evidence storage."""
    method: str = ""
    url: str = ""
    request_headers: Dict = field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0

    def format_request_dump(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        host = parsed.hostname or ""
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {host}"]
        for k, v in self.request_headers.items():
            if k.lower() == "host":
                continue
            display_v = v
            if k.lower() == "authorization" and len(v) > 40:
                display_v = v[:30] + "...[truncated]"
            lines.append(f"{k}: {display_v}")
        lines.append("")
        if self.request_body:
            lines.append(self.request_body)
        return "\n".join(lines)

    def format_response_dump(self) -> str:
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        body = self.response_body
        if len(body) > 2000:
            body = body[:2000] + "\n\n...[truncated — full response was {len(self.response_body)} bytes]"
        lines.append(body)
        return "\n".join(lines)


class HttpUtils:
    @staticmethod
    def send_request(method: str, url: str, headers: Dict,
                    params: Optional[Dict] = None,
                    json: Optional[Dict] = None,
                    timeout: int = 10,
                    allow_redirects: bool = True) -> httpx.Response:
        """Standardized request sending with error handling."""
        try:
            kwargs = {
                'headers': headers,
                'timeout': timeout,
                'follow_redirects': allow_redirects
            }
            if params:
                kwargs['params'] = params
            if json:
                kwargs['json'] = json

            with httpx.Client() as client:
                return client.request(method, url, **kwargs)

        except httpx.TimeoutException:
            raise
        except httpx.HTTPError as e:
            logging.error(f"Request failed: {e}")
            raise

    @staticmethod
    def send_request_recorded(method: str, url: str, headers: Dict,
                              params: Optional[Dict] = None,
                              json: Optional[Dict] = None,
                              timeout: int = 10,
                              allow_redirects: bool = True) -> tuple[httpx.Response, RequestRecord]:
        """Like send_request but also returns a RequestRecord for evidence."""
        record = RequestRecord(method=method.upper(), url=url, request_headers=dict(headers))
        if json:
            try:
                record.request_body = json_lib.dumps(json, indent=2)
            except Exception:
                record.request_body = str(json)
        if params:
            record.request_body = (record.request_body or "") + f"\nQuery Params: {params}"

        start = time.perf_counter()
        response = HttpUtils.send_request(method, url, headers, params=params, json=json,
                                          timeout=timeout, allow_redirects=allow_redirects)
        record.elapsed_ms = (time.perf_counter() - start) * 1000
        record.status_code = response.status_code
        record.response_headers = dict(response.headers)
        try:
            record.response_body = response.text
        except Exception:
            record.response_body = "<binary or undecodable>"
        return response, record

    @staticmethod
    def is_redirect_response(response: httpx.Response) -> bool:
        """Check if response is a redirect."""
        return response.status_code in [301, 302, 303, 307, 308]

    @staticmethod
    def extract_redirect_location(response: httpx.Response) -> Optional[str]:
        """Extract redirect location from response."""
        if HttpUtils.is_redirect_response(response):
            return response.headers.get('Location') or response.headers.get('location')
        return None
