"""Tests for bounded public web tools and SSRF protections."""
from __future__ import annotations
import json
import socket
import unittest
from unittest.mock import patch

import httpcore
import httpx

from core.errors import ToolExecutionError
from core.tool_registry import ToolRegistry
from tools.web import (
    _PinnedBackend,
    _validated_target,
    check_website_status,
    fetch_webpage,
    get_exchange_rate,
    register_web_tools,
    summarize_webpage,
)


def _dns_record(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


class WebToolTests(unittest.TestCase):
    def test_url_validation_rejects_non_https_and_credentialed_urls(self):
        for url in (
            "http://example.com/",
            "https://user:pass@example.com/",
            "https://example.com:8443/",
            "https://example.com/#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ToolExecutionError):
                _validated_target(url)

    @patch("tools.web.socket.getaddrinfo")
    def test_dns_resolution_blocks_private_or_mixed_answers(self, getaddrinfo):
        getaddrinfo.return_value = _dns_record("127.0.0.1")
        with self.assertRaisesRegex(ToolExecutionError, "Private"):
            _validated_target("https://example.com/")
        getaddrinfo.return_value = _dns_record("93.184.216.34") + _dns_record("10.0.0.2")
        with self.assertRaisesRegex(ToolExecutionError, "Private"):
            _validated_target("https://example.com/")

    @patch("httpcore.SyncBackend.connect_tcp")
    def test_pinned_backend_connects_to_validated_ip_not_dns_hostname(self, connect_tcp):
        sentinel = object()
        connect_tcp.return_value = sentinel
        backend = _PinnedBackend("example.com", "93.184.216.34")
        self.assertIs(backend.connect_tcp("example.com", 443), sentinel)
        self.assertEqual(connect_tcp.call_args.args[0], "93.184.216.34")
        with self.assertRaises(httpcore.ConnectError):
            backend.connect_tcp("attacker.example", 443)

    @patch("tools.web.socket.getaddrinfo", return_value=_dns_record("93.184.216.34"))
    @patch("tools.web.httpx.Client")
    def test_fetch_extracts_visible_html_and_marks_it_untrusted(self, client_factory, _resolver):
        response = client_factory.return_value.__enter__.return_value.stream.return_value.__enter__.return_value
        response.status_code = 200
        response.headers = {"content-type": "text/html; charset=utf-8"}
        response.iter_bytes.return_value = [
            b"<html><script>ignore me</script><h1>Title</h1><p>Hello &amp; welcome.</p></html>",
        ]
        result = fetch_webpage("https://example.com/?token=secret")
        self.assertEqual(result["text"], "Title\nHello & welcome.")
        self.assertTrue(result["content_is_untrusted"])
        self.assertIn("redacted", result["source_url"])
        self.assertNotIn("secret", result["source_url"])

    @patch("tools.web.socket.getaddrinfo", return_value=_dns_record("93.184.216.34"))
    @patch("tools.web.httpx.Client")
    def test_redirect_to_private_ip_is_blocked_before_follow_up_connection(self, client_factory, _resolver):
        response = client_factory.return_value.__enter__.return_value.stream.return_value.__enter__.return_value
        response.status_code = 302
        response.headers = {"location": "https://127.0.0.1/admin"}
        with self.assertRaisesRegex(ToolExecutionError, "Private"):
            fetch_webpage("https://example.com/")
        self.assertEqual(client_factory.call_count, 1)

    @patch("tools.web.socket.getaddrinfo", return_value=_dns_record("93.184.216.34"))
    @patch("tools.web.httpx.Client")
    def test_fetch_timeout_is_reported(self, client_factory, _resolver):
        client = client_factory.return_value.__enter__.return_value
        client.stream.side_effect = httpx.TimeoutException("timed out")
        with self.assertRaisesRegex(ToolExecutionError, "timed out"):
            fetch_webpage("https://example.com/")

    @patch("tools.web.socket.getaddrinfo", return_value=_dns_record("93.184.216.34"))
    @patch("tools.web.httpx.Client")
    def test_response_body_limit_and_redirect_limit(self, client_factory, _resolver):
        response = client_factory.return_value.__enter__.return_value.stream.return_value.__enter__.return_value
        response.status_code = 200
        response.headers = {"content-type": "text/html"}
        response.iter_bytes.return_value = [b"x" * 1_000_001]
        with self.assertRaisesRegex(ToolExecutionError, "size limit"):
            fetch_webpage("https://example.com/")

        response.status_code = 302
        response.headers = {"location": "https://example.com/next"}
        response.iter_bytes.return_value = []
        with patch("tools.web._MAX_REDIRECTS", 0):
            with self.assertRaisesRegex(ToolExecutionError, "redirect limit"):
                check_website_status("https://example.com/")

    @patch("tools.web._request_public_url")
    def test_exchange_rate_validates_and_returns_provider_metadata(self, request):
        request.return_value = {
            "body": json.dumps({"base": "USD", "date": "2025-01-01", "rates": {"EUR": 0.9}}).encode(),
            "status_code": 200,
            "final_url": "https://api.frankfurter.app/latest/USD?to=EUR",
            "retrieved_at": "2025-01-01T00:00:00+00:00",
        }
        result = get_exchange_rate("usd", "eur")
        self.assertEqual(result["rate"], 0.9)
        self.assertEqual(result["provider"], "frankfurter")
        with self.assertRaises(ToolExecutionError):
            get_exchange_rate("USD", "EUR", provider="custom")
        with self.assertRaises(ToolExecutionError):
            get_exchange_rate("US", "EUR")
        request.return_value["status_code"] = 503
        with self.assertRaisesRegex(ToolExecutionError, "HTTP 503"):
            get_exchange_rate("USD", "EUR")

    @patch("tools.web.fetch_webpage")
    def test_summary_is_bounded_and_registry_contains_external_tools(self, fetch):
        fetch.return_value = {
            "source_url": "https://example.com/",
            "retrieved_at": "now",
            "text": "First sentence. Second sentence. Third sentence.",
        }
        self.assertEqual(summarize_webpage("https://example.com/")["summary"], "First sentence. Second sentence. Third sentence.")
        registry = ToolRegistry()
        register_web_tools(registry)
        self.assertEqual(len(registry.list_tools()), 4)
        self.assertTrue(all(tool.permission_level == "external" for tool in registry.list_tools()))


if __name__ == "__main__":
    unittest.main()
