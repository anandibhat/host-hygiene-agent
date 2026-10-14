"""Tests for OS Baseline Filter (Noise Reduction)."""

import unittest
import json
import tempfile
import os
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.baseline.os_filter import OSBaselineFilter


class TestOSBaselineFilter(unittest.TestCase):

    def setUp(self):
        self.filter = OSBaselineFilter()

    def test_windows_baseline_filtering(self):
        procs = [
            ProcessInfo(pid=1, name="System"),
            ProcessInfo(pid=2, name="svchost.exe"),
            ProcessInfo(pid=3, name="lsass.exe"),
            ProcessInfo(pid=4, name="explorer.exe"),
            ProcessInfo(pid=5, name="my_custom_script.py"),
            ProcessInfo(pid=6, name="chrome.exe"),
        ]

        result = self.filter.filter_processes(procs, platform_name="windows")
        self.assertEqual(result.total_inspected, 6)
        self.assertEqual(result.noise_filtered_count, 4)
        self.assertEqual(len(result.candidate_processes), 2)

        candidate_names = [p.name for p in result.candidate_processes]
        self.assertIn("my_custom_script.py", candidate_names)
        self.assertIn("chrome.exe", candidate_names)
        self.assertNotIn("svchost.exe", candidate_names)
        self.assertAlmostEqual(result.noise_reduction_ratio, 4 / 6)

    def test_linux_baseline_filtering(self):
        procs = [
            ProcessInfo(pid=1, name="systemd"),
            ProcessInfo(pid=2, name="systemd-journald"),
            ProcessInfo(pid=3, name="kworker/0:1-events"),
            ProcessInfo(pid=4, name="cron"),
            ProcessInfo(pid=5, name="suspicious_miner"),
        ]

        result = self.filter.filter_processes(procs, platform_name="linux")
        self.assertEqual(result.noise_filtered_count, 4)
        self.assertEqual(len(result.candidate_processes), 1)
        self.assertEqual(result.candidate_processes[0].name, "suspicious_miner")

    def test_darwin_baseline_filtering(self):
        procs = [
            ProcessInfo(pid=1, name="launchd"),
            ProcessInfo(pid=2, name="WindowServer"),
            ProcessInfo(pid=3, name="cfprefsd"),
            ProcessInfo(pid=4, name="unknown_backdoor"),
        ]

        result = self.filter.filter_processes(procs, platform_name="darwin")
        self.assertEqual(result.noise_filtered_count, 3)
        self.assertEqual(len(result.candidate_processes), 1)
        self.assertEqual(result.candidate_processes[0].name, "unknown_backdoor")

    def test_custom_whitelist(self):
        f = OSBaselineFilter(custom_whitelist=["internal_service.exe", "custom_monitor"])
        proc1 = ProcessInfo(pid=10, name="internal_service.exe")
        proc2 = ProcessInfo(pid=11, name="custom_monitor")
        proc3 = ProcessInfo(pid=12, name="unknown.exe")

        self.assertTrue(f.is_baseline(proc1, "windows"))
        self.assertTrue(f.is_baseline(proc2, "linux"))
        self.assertFalse(f.is_baseline(proc3, "windows"))

    def test_custom_whitelist_json_file(self):
        temp_file = tempfile.mktemp(suffix=".json")
        try:
            with open(temp_file, "w") as fp:
                json.dump({"whitelist": ["corp_agent.exe", "corp_edr"]}, fp)

            f = OSBaselineFilter()
            f.load_custom_baseline_file(temp_file)

            p1 = ProcessInfo(pid=20, name="corp_agent.exe")
            p2 = ProcessInfo(pid=21, name="corp_edr")
            self.assertTrue(f.is_baseline(p1, "windows"))
            self.assertTrue(f.is_baseline(p2, "linux"))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)


if __name__ == "__main__":
    unittest.main()
