"""Tests for read-only network and process diagnostics."""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx

from core.errors import ToolExecutionError
from core.tool_registry import ToolRegistry
from tools.network_diagnostics import (
    check_internet_connectivity,
    get_network_interfaces,
    get_system_uptime,
    inspect_process,
    register_network_diagnostic_tools,
)


class NetworkDiagnosticTests(unittest.TestCase):
    @patch("tools.network_diagnostics.psutil.net_io_counters")
    @patch("tools.network_diagnostics.psutil.net_if_stats")
    def test_interfaces_return_status_and_counters_without_addresses(self, stats, counters):
        stats.return_value = {"eth0": SimpleNamespace(isup=True, speed=1000, mtu=1500)}
        counters.return_value = {
            "eth0": SimpleNamespace(
                bytes_sent=10, bytes_recv=20, packets_sent=1, packets_recv=2,
                errin=0, errout=0, dropin=0, dropout=0,
            ),
        }
        result = get_network_interfaces()
        self.assertTrue(result["interfaces"][0]["is_up"])
        self.assertEqual(result["interfaces"][0]["bytes_received"], 20)
        self.assertNotIn("addresses", result["interfaces"][0])

    @patch("tools.network_diagnostics.httpx.Client")
    def test_connectivity_success_disables_redirects_and_proxies(self, client_factory):
        client = client_factory.return_value.__enter__.return_value
        client.stream.return_value.__enter__.return_value.status_code = 204
        result = check_internet_connectivity()
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status_code"], 204)
        self.assertFalse(client_factory.call_args.kwargs["follow_redirects"])
        self.assertFalse(client_factory.call_args.kwargs["trust_env"])

    @patch("tools.network_diagnostics.httpx.Client")
    def test_connectivity_failure_and_untrusted_endpoint(self, client_factory):
        client = client_factory.return_value.__enter__.return_value
        client.stream.side_effect = httpx.TimeoutException("timeout")
        result = check_internet_connectivity()
        self.assertFalse(result["reachable"])
        self.assertEqual(result["error"], "timeout")
        with self.assertRaises(ToolExecutionError):
            check_internet_connectivity("http://127.0.0.1/")

    @patch("tools.network_diagnostics.psutil.Process")
    def test_process_inspection_reports_resource_usage_only(self, process_factory):
        process = process_factory.return_value
        process.oneshot.return_value = nullcontext()
        process.name.return_value = "worker"
        process.status.return_value = "running"
        process.cpu_percent.return_value = 5
        process.memory_info.return_value = SimpleNamespace(rss=1024)
        process.memory_percent.return_value = 1.5
        process.num_threads.return_value = 3
        result = inspect_process(123)
        self.assertEqual(result["memory_bytes"], 1024)
        self.assertNotIn("cmdline", result)
        self.assertNotIn("environment", result)

    @patch("tools.network_diagnostics.psutil.Process")
    def test_invalid_missing_and_denied_processes(self, process_factory):
        with self.assertRaises(ToolExecutionError):
            inspect_process(0)
        import psutil

        process_factory.side_effect = psutil.NoSuchProcess(123)
        with self.assertRaisesRegex(ToolExecutionError, "no longer exists"):
            inspect_process(123)
        process_factory.side_effect = psutil.AccessDenied(123)
        with self.assertRaisesRegex(ToolExecutionError, "Permission"):
            inspect_process(123)

    @patch("tools.network_diagnostics.psutil.boot_time", return_value=100)
    @patch("tools.network_diagnostics.time.time", return_value=90_161)
    def test_uptime_is_reported_in_seconds_and_human_format(self, _now, _boot_time):
        self.assertEqual(get_system_uptime()["uptime_human"], "1d 1h 1m 1s")

    def test_diagnostics_tools_are_registered_read_only(self):
        registry = ToolRegistry()
        register_network_diagnostic_tools(registry)
        self.assertEqual(len(registry.list_tools()), 4)
        self.assertTrue(all(tool.permission_level == "read" for tool in registry.list_tools()))


if __name__ == "__main__":
    unittest.main()
