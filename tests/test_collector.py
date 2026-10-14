"""Tests for Process Collectors."""

import unittest
import os
import tempfile
import shutil
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.collector.factory import CollectorFactory
from host_hygiene.collector.windows import WindowsProcessCollector
from host_hygiene.collector.linux import LinuxProcessCollector
from host_hygiene.collector.darwin import DarwinProcessCollector


class TestProcessCollector(unittest.TestCase):

    def test_process_info_clean_name(self):
        p1 = ProcessInfo(pid=100, name="svchost.exe")
        self.assertEqual(p1.clean_name, "svchost")

        p2 = ProcessInfo(pid=200, name="Systemd-Journald")
        self.assertEqual(p2.clean_name, "systemd-journald")

        p3 = ProcessInfo(pid=300, name="  CHROME.EXE  ")
        self.assertEqual(p3.clean_name, "chrome")

    def test_collector_factory(self):
        win_col = CollectorFactory.get_collector("windows")
        self.assertIsInstance(win_col, WindowsProcessCollector)
        self.assertEqual(win_col.get_platform_name(), "windows")

        lin_col = CollectorFactory.get_collector("linux")
        self.assertIsInstance(lin_col, LinuxProcessCollector)
        self.assertEqual(lin_col.get_platform_name(), "linux")

        mac_col = CollectorFactory.get_collector("darwin")
        self.assertIsInstance(mac_col, DarwinProcessCollector)
        self.assertEqual(mac_col.get_platform_name(), "darwin")

    def test_linux_collector_with_mock_proc(self):
        """Test Linux procfs parsing using a mocked directory structure."""
        temp_proc = tempfile.mkdtemp()
        try:
            # Create mock /proc/1234
            pid_dir = os.path.join(temp_proc, "1234")
            os.makedirs(pid_dir, exist_ok=True)
            with open(os.path.join(pid_dir, "comm"), "w") as f:
                f.write("nginx\n")
            with open(os.path.join(pid_dir, "cmdline"), "wb") as f:
                f.write(b"nginx\x00-g\x00daemon off;\x00")
            with open(os.path.join(pid_dir, "status"), "w") as f:
                f.write("Name:\tnginx\nPPid:\t1\n")

            # Create mock non-numeric dir (should be skipped)
            os.makedirs(os.path.join(temp_proc, "sys"), exist_ok=True)

            collector = LinuxProcessCollector(proc_path=temp_proc)
            processes = collector.collect()

            self.assertEqual(len(processes), 1)
            p = processes[0]
            self.assertEqual(p.pid, 1234)
            self.assertEqual(p.name, "nginx")
            self.assertEqual(p.ppid, 1)
            self.assertIn("daemon off;", p.cmdline)
        finally:
            shutil.rmtree(temp_proc)

    def test_live_collection_returns_processes(self):
        """Verify the active collector returns processes on the current host."""
        collector = CollectorFactory.get_collector()
        processes = collector.collect()
        self.assertGreater(len(processes), 0)
        # Verify all collected items have valid PID and name
        for p in processes:
            self.assertIsInstance(p.pid, int)
            self.assertIsInstance(p.name, str)
            self.assertTrue(len(p.name) > 0)


if __name__ == "__main__":
    unittest.main()
