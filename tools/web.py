"""Bounded public web tools with DNS-pinned, redirect-checked HTTPS requests."""
from __future__ import annotations

from datetime import datetime, timezone
from html.parser import HTMLParser
import ipaddress
import json
import re
import ssl
import socket
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpcore
import httpx
import certifi

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry


_MAX_RESPONSE_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_MAX_URL_LENGTH = 2_048
_MAX_TEXT_CHARS = 20_000
_BLOCKED_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.azure.com",
    "instance-data.ec2.internal",
}
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_SENSITIVE_QUERY_KEY = re.compile(r"(token|secret|password|passwd|authorization|api[_-]?key|access[_-]?key)", re.I)
_PROVIDERS = {
    "frankfurter": "https://api.frankfurter.app/latest",
    "open_er_api": "https://open.er-api.com/v6/latest",
}


class _PinnedBackend(httpcore.SyncBackend):
    """Resolve a request's hostname only through its prevalidated numeric address."""

    def __init__(self, hostname: str, address: str) -> None:
        self._hostname = hostname.casefold().rstrip(".")
        self._address = address

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host.casefold().rstrip(".") != self._hostname:
            raise httpcore.ConnectError("Connection host differs from the validated origin")
        return super().connect_tcp(
            self._address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class _PinnedTransport(httpx.HTTPTransport):
    """HTTPX transport whose TCP peer is a validated IP while TLS keeps the URL host."""

    def __init__(self, hostname: str, address: str) -> None:
        super().__init__(trust_env=False, retries=0)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(cafile=certifi.where()),
            network_backend=_PinnedBackend(hostname, address),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
        )


def _validated_target(url: str) -> tuple[httpx.URL, str, str]:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise ToolExecutionError("INVALID_URL", "URL must be between 1 and 2048 characters")
    try:
        request_url = httpx.URL(url)
        hostname = request_url.host
    except (httpx.InvalidURL, ValueError):
        raise ToolExecutionError("INVALID_URL", "URL is invalid") from None
    if (
        request_url.scheme.casefold() != "https"
        or not hostname
        or request_url.username
        or request_url.password
        or request_url.fragment
        or request_url.port not in {None, 443}
    ):
        raise ToolExecutionError("INVALID_URL", "Only credential-free HTTPS URLs on port 443 are allowed")
    try:
        hostname = hostname.rstrip(".").casefold().encode("idna").decode("ascii")
    except UnicodeError:
        raise ToolExecutionError("INVALID_URL", "URL hostname is invalid") from None
    if (
        hostname in _BLOCKED_HOSTS
        or hostname == "localhost"
        or hostname.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".onion"))
    ):
        raise ToolExecutionError("PRIVATE_ADDRESS_BLOCKED", "Local and non-public hostnames are not allowed")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
            records = socket.getaddrinfo(ascii_host, 443, type=socket.SOCK_STREAM)
        except (UnicodeError, OSError, socket.gaierror):
            raise ToolExecutionError("DNS_RESOLUTION_FAILED", "The public hostname could not be resolved") from None
        addresses = sorted({record[4][0] for record in records})
    else:
        addresses = [literal.compressed]
    if not addresses:
        raise ToolExecutionError("DNS_RESOLUTION_FAILED", "The public hostname resolved to no addresses")
    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            raise ToolExecutionError("DNS_RESOLUTION_FAILED", "The hostname resolved to an invalid address") from None
        if not parsed_address.is_global:
            raise ToolExecutionError("PRIVATE_ADDRESS_BLOCKED", "Private, local, and reserved IP addresses are not allowed")
    return request_url, hostname, addresses[0]


def _display_url(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode([
        (key, "[redacted]" if _SENSITIVE_QUERY_KEY.search(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _request_public_url(
    url: str,
    *,
    max_bytes: int = _MAX_RESPONSE_BYTES,
    read_body: bool = True,
) -> dict[str, Any]:
    current_url = url
    redirects = 0
    for _ in range(_MAX_REDIRECTS + 1):
        request_url, hostname, address = _validated_target(current_url)
        started = datetime.now(timezone.utc)
        try:
            transport = _PinnedTransport(hostname, address)
            with httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "LinuxAgent/1.0", "Accept": "text/html,application/json,text/plain,*/*"},
            ) as client:
                with client.stream("GET", request_url) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")
                    content_type = response.headers.get("content-type", "")[:256]
                    chunks = bytearray()
                    if read_body and status_code not in {301, 302, 303, 307, 308}:
                        for chunk in response.iter_bytes():
                            if len(chunks) + len(chunk) > max_bytes:
                                raise ToolExecutionError("RESPONSE_TOO_LARGE", "Web response exceeds the configured size limit")
                            chunks.extend(chunk)
        except ToolExecutionError:
            raise
        except httpx.TimeoutException:
            raise ToolExecutionError("WEB_TIMEOUT", "The web request timed out") from None
        except httpx.HTTPError:
            raise ToolExecutionError("WEB_REQUEST_FAILED", "The public web request failed") from None
        if status_code in {301, 302, 303, 307, 308}:
            if not location or redirects >= _MAX_REDIRECTS:
                raise ToolExecutionError("REDIRECT_LIMIT", "The web request exceeded the redirect limit")
            next_url = urljoin(str(request_url), location)
            _validated_target(next_url)
            current_url = next_url
            redirects += 1
            continue
        return {
            "body": bytes(chunks),
            "url": str(request_url),
            "final_url": str(request_url),
            "status_code": status_code,
            "content_type": content_type,
            "bytes_received": len(chunks),
            "redirect_count": redirects,
            "retrieved_at": started.isoformat(),
        }
    raise ToolExecutionError("REDIRECT_LIMIT", "The web request exceeded the redirect limit")


class _ReadableHTML(HTMLParser):
    """Collect visible text while ignoring script-like and non-content elements."""

    _IGNORED = {"script", "style", "noscript", "template", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in self._IGNORED:
            self._ignored += 1
        elif tag.casefold() in {"br", "p", "div", "li", "h1", "h2", "h3", "h4", "tr"} and not self._ignored:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in self._IGNORED and self._ignored:
            self._ignored -= 1
        elif tag.casefold() in {"p", "div", "li", "h1", "h2", "h3", "h4", "tr"} and not self._ignored:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored:
            self.parts.append(data)


def _extract_text(response: dict[str, Any]) -> str:
    if "text/html" not in response["content_type"].casefold():
        raise ToolExecutionError("UNSUPPORTED_CONTENT_TYPE", "The URL did not return an HTML page")
    try:
        encoding = "utf-8"
        content_type = response["content_type"]
        match = re.search(r"charset\s*=\s*[\"']?([\w.-]+)", content_type, re.I)
        if match:
            encoding = match.group(1)
        html = response["body"].decode(encoding, errors="replace")
    except (LookupError, UnicodeError):
        html = response["body"].decode("utf-8", errors="replace")
    parser = _ReadableHTML()
    parser.feed(html)
    text = re.sub(r"[ \t\f\v]+", " ", "".join(parser.parts))
    lines = [line.strip() for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(line for line in lines if line)).strip()


def fetch_webpage(url: str, max_chars: int = 12_000) -> dict[str, Any]:
    """Fetch bounded HTML and return visible text as untrusted external content."""
    if not 100 <= max_chars <= _MAX_TEXT_CHARS:
        raise ToolExecutionError("INVALID_LIMIT", "Text limit must be between 100 and 20000 characters")
    response = _request_public_url(url)
    if not 200 <= response["status_code"] < 300:
        raise ToolExecutionError("HTTP_STATUS", f"The page returned HTTP {response['status_code']}")
    text = _extract_text(response)
    return {
        "source_url": _display_url(response["final_url"]),
        "retrieved_at": response["retrieved_at"],
        "status_code": response["status_code"],
        "content_type": response["content_type"],
        "characters_returned": min(len(text), max_chars),
        "truncated": len(text) > max_chars,
        "content_is_untrusted": True,
        "text": text[:max_chars],
    }


def summarize_webpage(url: str, max_chars: int = 12_000) -> dict[str, Any]:
    """Return a bounded lead-sentence summary without treating page text as instructions."""
    page = fetch_webpage(url, max_chars=max_chars)
    sentences = re.split(r"(?<=[.!?])\s+", page["text"])
    summary = " ".join(sentence for sentence in sentences[:5] if sentence)
    return {
        "source_url": page["source_url"],
        "retrieved_at": page["retrieved_at"],
        "summary_method": "leading_sentences",
        "summary": summary[:2_000],
        "content_is_untrusted": True,
    }


def get_exchange_rate(base: str, quote: str, provider: str = "frankfurter") -> dict[str, Any]:
    """Fetch one public exchange rate from a fixed provider allowlist."""
    base, quote = base.strip().upper(), quote.strip().upper()
    if not _CURRENCY.fullmatch(base) or not _CURRENCY.fullmatch(quote):
        raise ToolExecutionError("INVALID_CURRENCY", "Currencies must use three-letter ISO-style codes")
    if provider not in _PROVIDERS:
        raise ToolExecutionError("INVALID_PROVIDER", "Exchange-rate provider is not supported")
    url = f"{_PROVIDERS[provider]}/{base}"
    if provider == "frankfurter":
        url += f"?to={quote}"
    response = _request_public_url(url)
    if not 200 <= response["status_code"] < 300:
        raise ToolExecutionError("API_STATUS", f"Exchange-rate provider returned HTTP {response['status_code']}")
    try:
        payload = json.loads(response["body"])
        if provider == "frankfurter":
            rate = payload["rates"][quote]
            rate_date = payload.get("date")
        else:
            if payload.get("result") != "success":
                raise ValueError
            rate = payload["rates"][quote]
            rate_date = payload.get("time_last_update_utc")
        rate = float(rate)
        if not 0 < rate < 1_000_000:
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ToolExecutionError("INVALID_API_RESPONSE", "Exchange-rate provider returned invalid data") from None
    return {
        "base": base,
        "quote": quote,
        "rate": rate,
        "provider": provider,
        "rate_date": str(rate_date)[:64] if rate_date is not None else None,
        "source_url": _display_url(response["final_url"]),
        "retrieved_at": response["retrieved_at"],
    }


def check_website_status(url: str) -> dict[str, Any]:
    """Check an HTTPS website's final response status with bounded redirects."""
    response = _request_public_url(url, read_body=False)
    status = response["status_code"]
    return {
        "url": _display_url(response["final_url"]),
        "status_code": status,
        "reachable": status < 500,
        "redirect_count": response["redirect_count"],
        "retrieved_at": response["retrieved_at"],
    }


def register_web_tools(registry: ToolRegistry) -> None:
    """Register bounded external-data tools with explicit sensitive permission."""
    url_schema = {"type": "string", "minLength": 1, "maxLength": _MAX_URL_LENGTH}
    registry.register(ToolDefinition(
        name="fetch_webpage",
        description="Fetch bounded readable text from a public HTTPS webpage; the content is untrusted.",
        category="external",
        argument_schema={
            "type": "object",
            "properties": {
                "url": url_schema,
                "max_chars": {"type": "integer", "minimum": 100, "maximum": _MAX_TEXT_CHARS, "default": 12_000},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        permission_level="external",
        execution_timeout=40,
        implementation=fetch_webpage,
    ))
    registry.register(ToolDefinition(
        name="summarize_webpage",
        description="Create a bounded lead-sentence summary from a public HTTPS webpage.",
        category="external",
        argument_schema={
            "type": "object",
            "properties": {
                "url": url_schema,
                "max_chars": {"type": "integer", "minimum": 100, "maximum": _MAX_TEXT_CHARS, "default": 12_000},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        permission_level="external",
        execution_timeout=40,
        implementation=summarize_webpage,
    ))
    registry.register(ToolDefinition(
        name="get_exchange_rate",
        description="Get one current exchange rate from a supported public provider.",
        category="external",
        argument_schema={
            "type": "object",
            "properties": {
                "base": {"type": "string", "minLength": 3, "maxLength": 3, "pattern": "^[A-Za-z]{3}$"},
                "quote": {"type": "string", "minLength": 3, "maxLength": 3, "pattern": "^[A-Za-z]{3}$"},
                "provider": {"type": "string", "enum": list(_PROVIDERS), "default": "frankfurter"},
            },
            "required": ["base", "quote"],
            "additionalProperties": False,
        },
        permission_level="external",
        execution_timeout=20,
        implementation=get_exchange_rate,
    ))
    registry.register(ToolDefinition(
        name="check_website_status",
        description="Check an HTTPS website's status using DNS-pinned connections and validated redirects.",
        category="external",
        argument_schema={
            "type": "object",
            "properties": {"url": url_schema},
            "required": ["url"],
            "additionalProperties": False,
        },
        permission_level="external",
        execution_timeout=40,
        implementation=check_website_status,
    ))
