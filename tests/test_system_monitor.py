"""Tests for bounded, read-only system monitoring tools."""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core.errors import ToolExecutionError
from core.tool_registry import ToolRegistry
from tools.system_monitor import (
    get_cpu_details,
    get_disk_details,
    get_memory_details,
    list_processes,
    register_system_monitor_tools,
)


class SystemMonitorTests(unittest.TestCase):
    @patch("tools.system_monitor.psutil.cpu_percent", return_value=23.5)
    @patch("tools.system_monitor.psutil.cpu_count", side_effect=[4, 8])
    def test_cpu_usage_and_core_counts(self, _counts, _usage):
        self.assertEqual(get_cpu_details(), {
            "usage_percent": 23.5,
            "logical_cores": 8,
            "physical_cores": 4,
        })

    @patch("tools.system_monitor.psutil.swap_memory")
    @patch("tools.system_monitor.psutil.virtual_memory")
    def test_memory_reports_ram_swap_and_human_readable_sizes(self, virtual, swap):
        virtual.return_value = SimpleNamespace(total=2048, used=1024, available=1024, percent=50)
        swap.return_value = SimpleNamespace(total=1024, used=256, free=768, percent=25)
        result = get_memory_details()
        self.assertEqual(result["ram"]["total_readable"], "2.0 KB")
        self.assertEqual(result["swap"]["used_percent"], 25)

    @patch("tools.system_monitor.psutil.disk_usage")
    @patch("tools.system_monitor.psutil.disk_partitions")
    def test_disk_details_skip_inaccessible_mounts_and_bound_results(self, partitions, disk_usage):
        partitions.return_value = [
            SimpleNamespace(mountpoint="/", fstype="ext4"),
            SimpleNamespace(mountpoint="/secret", fstype="nfs"),
        ]
        disk_usage.side_effect = [
            SimpleNamespace(total=4096, used=1024, free=3072, percent=25),
            PermissionError,
        ]
        result = get_disk_details(limit=1)
        self.assertEqual(len(result["filesystems"]), 1)
        self.assertEqual(result["filesystems"][0]["free_readable"], "3.0 KB")
        self.assertEqual(result["skipped"], 1)
        with self.assertRaises(ToolExecutionError):
            get_disk_details(limit=51)

    @patch("tools.system_monitor.psutil.process_iter")
    def test_processes_sort_by_memory_and_exclude_sensitive_fields(self, process_iter):
        processes = [
            SimpleNamespace(info={
                "pid": 20, "name": "worker", "cpu_percent": 90, "memory_percent": 10,
                "memory_info": SimpleNamespace(rss=500),
            }),
            SimpleNamespace(info={
                "pid": 10, "name": "browser", "cpu_percent": 20, "memory_percent": 40,
                "memory_info": SimpleNamespace(rss=900),
            }),
        ]
        process_iter.return_value = processes
        result = list_processes(sort_by="memory", limit=1)
        self.assertEqual(result["processes"][0]["pid"], 10)
        self.assertNotIn("cmdline", result["processes"][0])
        self.assertNotIn("environment", result["processes"][0])

    @patch("tools.system_monitor.psutil.process_iter", return_value=[])
    def test_empty_process_list_and_invalid_sort(self, _process_iter):
        self.assertEqual(list_processes()["processes"], [])
        with self.assertRaises(ToolExecutionError):
            list_processes(sort_by="disk")

    def test_monitoring_tools_are_registered_read_only(self):
        registry = ToolRegistry()
        register_system_monitor_tools(registry)
        definitions = registry.list_tools()
        self.assertEqual(len(definitions), 4)
        self.assertTrue(all(tool.permission_level == "read" for tool in definitions))


if __name__ == "__main__":
    unittest.main()
