"""Tests for Triage Engines (Offline Rule-Based and AI Triage)."""

import unittest
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.detector.anomaly_engine import AnomalyFinding
from host_hygiene.triage.offline_triage import OfflineTriageEngine
from host_hygiene.triage.ai_triage import AITriageEngine


class TestTriage(unittest.TestCase):

    def setUp(self):
        self.offline = OfflineTriageEngine()

    def test_offline_triage_clean_host(self):
        procs = [
            ProcessInfo(pid=100, name="chrome.exe"),
            ProcessInfo(pid=101, name="python.exe"),
        ]
        report = self.offline.triage(
            candidate_processes=procs,
            anomalies_by_pid={},
            total_inspected=50,
            noise_filtered_count=48,
            platform_name="windows",
        )

        self.assertEqual(report.hygiene_score, 100)
        self.assertEqual(report.overall_risk, "Benign")
        self.assertEqual(len(report.evaluated_processes), 2)
        for ep in report.evaluated_processes:
            self.assertEqual(ep.risk_rating, "Benign")
            if "chrome" in ep.process_name:
                self.assertIn("web browser", ep.purpose.lower())
            elif "python" in ep.process_name:
                self.assertIn("python", ep.purpose.lower())

    def test_offline_triage_malicious_and_hygiene_score_drop(self):
        procs = [
            ProcessInfo(pid=666, name="svch0st.exe"),
            ProcessInfo(pid=777, name="mimikatz.exe"),
        ]
        anomalies = {
            666: [
                AnomalyFinding(
                    process_pid=666,
                    process_name="svch0st.exe",
                    anomaly_type="HOMOGLYPH_TYPOSQUATTING",
                    severity="CRITICAL",
                    description="Typosquatting core svchost",
                    target_os_component="svchost",
                )
            ],
            777: [
                AnomalyFinding(
                    process_pid=777,
                    process_name="mimikatz.exe",
                    anomaly_type="IOC_MATCH",
                    severity="CRITICAL",
                    description="Known credential dumper",
                )
            ],
        }

        report = self.offline.triage(
            candidate_processes=procs,
            anomalies_by_pid=anomalies,
            total_inspected=60,
            noise_filtered_count=58,
            platform_name="windows",
        )

        # Critical threats should penalize score severely
        self.assertLess(report.hygiene_score, 50)
        self.assertEqual(report.overall_risk, "Critical")
        self.assertEqual(len(report.host_recommendations), 3)

        # Check process evaluation details
        p666 = next(p for p in report.evaluated_processes if p.pid == 666)
        self.assertEqual(p666.risk_rating, "Malicious")
        self.assertTrue(len(p666.actionable_recommendations) > 0)
        self.assertTrue(any("Terminate" in r for r in p666.actionable_recommendations))

    def test_ai_triage_prompt_construction(self):
        ai_engine = AITriageEngine(api_key="mock_key", model="gemini-2.5-flash")
        procs = [ProcessInfo(pid=999, name="suspicious_proc.exe")]
        prompt = ai_engine._build_prompt(
            candidate_processes=procs,
            anomalies_by_pid={},
            total_inspected=10,
            noise_filtered_count=9,
            platform_name="windows",
        )
        self.assertIn("Daily Hygiene Score", prompt)
        self.assertIn("suspicious_proc.exe", prompt)
        self.assertIn("Risk rating", prompt)
        self.assertIn("Benign", prompt)
        self.assertIn("Malicious", prompt)

    def test_ai_triage_json_parsing(self):
        ai_engine = AITriageEngine(api_key="mock_key")
        markdown_json = """```json
{
  "daily_hygiene_score": 92,
  "overall_risk": "Benign",
  "summary": "Host processes appear normal.",
  "host_recommendations": ["Audit regularly."],
  "processes": [
    {
      "pid": 500,
      "process_name": "app.exe",
      "purpose": "Application server",
      "risk_rating": "Benign",
      "reasoning": "Standard binary",
      "actionable_recommendations": []
    }
  ]
}
```"""
        parsed = ai_engine._parse_json_response(markdown_json)
        self.assertEqual(parsed["daily_hygiene_score"], 92)
        self.assertEqual(parsed["overall_risk"], "Benign")
        self.assertEqual(len(parsed["processes"]), 1)

    def test_ai_triage_fallback_when_no_key(self):
        ai_engine = AITriageEngine(api_key=None, offline_fallback=True)
        # Without API key, should cleanly delegate to offline engine
        procs = [ProcessInfo(pid=10, name="slack.exe")]
        report = ai_engine.triage(
            candidate_processes=procs,
            anomalies_by_pid={},
            total_inspected=20,
            noise_filtered_count=19,
            platform_name="windows",
        )
        self.assertEqual(report.mode, "offline_fallback")
        self.assertEqual(report.hygiene_score, 100)


if __name__ == "__main__":
    unittest.main()
