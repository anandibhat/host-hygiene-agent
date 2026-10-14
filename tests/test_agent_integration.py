"""Integration tests for HostHygieneAgent."""

import unittest
import tempfile
import os
import json
from host_hygiene.agent import HostHygieneAgent
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.reporter.json_exporter import JSONExporter


class TestAgentIntegration(unittest.TestCase):

    def test_end_to_end_assessment_with_simulated_workload(self):
        """Simulate a realistic endpoint containing baseline noise, normal apps, and malware/typosquatting."""
        simulated_processes = [
            # Standard OS background noise
            ProcessInfo(pid=4, name="System"),
            ProcessInfo(pid=800, name="smss.exe"),
            ProcessInfo(pid=900, name="csrss.exe"),
            ProcessInfo(pid=1000, name="services.exe"),
            ProcessInfo(pid=1100, name="lsass.exe"),
            ProcessInfo(pid=1200, name="svchost.exe"),
            ProcessInfo(pid=1300, name="svchost.exe"),
            ProcessInfo(pid=1400, name="explorer.exe"),
            # Benign user software
            ProcessInfo(pid=2000, name="chrome.exe"),
            ProcessInfo(pid=2001, name="code.exe"),
            ProcessInfo(pid=2002, name="python.exe"),
            # Suspicious & Malicious threats
            ProcessInfo(pid=9001, name="svch0st.exe"),                 # Typosquatting
            ProcessInfo(pid=9002, name="mimikatz.exe"),                # Known IOC
            ProcessInfo(pid=9003, name="financial_report.pdf.exe"),     # Double extension
            ProcessInfo(pid=9004, name="xmrig.exe"),                   # Cryptominer IOC
        ]

        agent = HostHygieneAgent(
            platform_override="windows",
            force_offline=True,
        )

        report, anomalies = agent.run_hygiene_assessment(mock_processes=simulated_processes)

        # Verification of Lifecycle Stages:
        # 1. Total inspected
        self.assertEqual(report.total_inspected, 15)

        # 2. Noise filtered (8 OS components)
        self.assertEqual(report.noise_filtered_count, 8)
        self.assertAlmostEqual(report.noise_filtered_count / report.total_inspected, 8 / 15)

        # 3. Candidates (7 remaining: 3 benign + 4 threats)
        self.assertEqual(report.candidate_count, 7)

        # 4. Anomalies detected
        self.assertIn(9001, anomalies)
        self.assertIn(9002, anomalies)
        self.assertIn(9003, anomalies)
        self.assertIn(9004, anomalies)

        # 5. Hygiene Score & Risk
        self.assertEqual(report.overall_risk, "Critical")
        self.assertLess(report.hygiene_score, 40)

        # 6. JSON Export
        temp_json = tempfile.mktemp(suffix=".json")
        try:
            JSONExporter.export(report, "windows", anomalies, temp_json)
            self.assertTrue(os.path.isfile(temp_json))
            with open(temp_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["hygiene_score"], report.hygiene_score)
            self.assertEqual(data["overall_risk"], "Critical")
            self.assertEqual(len(data["all_anomalies"]), report.anomalies_detected_count)
        finally:
            if os.path.exists(temp_json):
                os.remove(temp_json)

    def test_live_host_assessment(self):
        """Run full agent assessment against the live host environment."""
        agent = HostHygieneAgent(force_offline=True)
        report, anomalies = agent.run_hygiene_assessment()

        self.assertGreater(report.total_inspected, 0)
        self.assertGreater(report.noise_filtered_count, 0)
        self.assertGreaterEqual(report.hygiene_score, 0)
        self.assertLessEqual(report.hygiene_score, 100)


if __name__ == "__main__":
    unittest.main()
