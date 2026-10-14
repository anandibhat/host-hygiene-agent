"""Tests for Anomaly Detection (Typosquatting, Homoglyphs, IOCs, Patterns)."""

import unittest
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.detector.anomaly_engine import AnomalyDetectionEngine
from host_hygiene.detector.similarity import (
    normalize_homoglyphs,
    damerau_levenshtein_distance,
    calculate_similarity,
)


class TestAnomalyDetection(unittest.TestCase):

    def setUp(self):
        self.engine_win = AnomalyDetectionEngine(platform_name="windows")
        self.engine_lin = AnomalyDetectionEngine(platform_name="linux")

    def test_homoglyph_normalization(self):
        self.assertEqual(normalize_homoglyphs("svch0st"), "svchost")
        self.assertEqual(normalize_homoglyphs("1sass"), "lsass")
        self.assertEqual(normalize_homoglyphs("expl0rer"), "explorer")
        self.assertEqual(normalize_homoglyphs("systemcl"), "systemd")

    def test_damerau_levenshtein(self):
        self.assertEqual(damerau_levenshtein_distance("svchost", "svchost"), 0)
        self.assertEqual(damerau_levenshtein_distance("svchost", "svchostt"), 1)
        # Transposition
        self.assertEqual(damerau_levenshtein_distance("svchost", "scvhost"), 1)
        self.assertEqual(damerau_levenshtein_distance("lsass", "lsasss"), 1)

    def test_flag_homoglyph_typosquatting_svch0st(self):
        """Specifically tests the requirement: Flag typosquatting like 'svch0st'."""
        proc = ProcessInfo(pid=1001, name="svch0st.exe")
        findings = self.engine_win.analyze_process(proc)

        self.assertGreater(len(findings), 0)
        types = [f.anomaly_type for f in findings]
        self.assertIn("HOMOGLYPH_TYPOSQUATTING", types)
        
        typo_f = next(f for f in findings if f.anomaly_type == "HOMOGLYPH_TYPOSQUATTING")
        self.assertEqual(typo_f.severity, "CRITICAL")
        self.assertEqual(typo_f.target_os_component, "svchost")

    def test_flag_typosquatting_distance_variants(self):
        # svchostt.exe (addition)
        proc1 = ProcessInfo(pid=1002, name="svchostt.exe")
        findings1 = self.engine_win.analyze_process(proc1)
        self.assertTrue(any(f.anomaly_type == "TYPOSQUATTING" for f in findings1))

        # scvhost.exe (transposition)
        proc2 = ProcessInfo(pid=1003, name="scvhost.exe")
        findings2 = self.engine_win.analyze_process(proc2)
        self.assertTrue(any(f.anomaly_type == "TYPOSQUATTING" for f in findings2))

        # lsasss.exe (addition)
        proc3 = ProcessInfo(pid=1004, name="lsasss.exe")
        findings3 = self.engine_win.analyze_process(proc3)
        self.assertTrue(any(f.anomaly_type == "TYPOSQUATTING" for f in findings3))

        # systemdd on Linux
        proc4 = ProcessInfo(pid=1005, name="systemdd")
        findings4 = self.engine_lin.analyze_process(proc4)
        self.assertTrue(any(f.anomaly_type == "TYPOSQUATTING" for f in findings4))

    def test_flag_masquerading_suffix(self):
        proc = ProcessInfo(pid=1006, name="svchost32.exe")
        findings = self.engine_win.analyze_process(proc)
        self.assertTrue(any(f.anomaly_type == "MASQUERADING_SUFFIX" for f in findings))

    def test_flag_known_ioc_names(self):
        # mimikatz
        p1 = ProcessInfo(pid=2001, name="mimikatz.exe")
        f1 = self.engine_win.analyze_process(p1)
        self.assertTrue(any(f.anomaly_type == "IOC_MATCH" and f.severity == "CRITICAL" for f in f1))

        # xmrig (cryptominer)
        p2 = ProcessInfo(pid=2002, name="xmrig")
        f2 = self.engine_lin.analyze_process(p2)
        self.assertTrue(any(f.anomaly_type == "IOC_MATCH" for f in f2))

        # beacon
        p3 = ProcessInfo(pid=2003, name="beacon.exe")
        f3 = self.engine_win.analyze_process(p3)
        self.assertTrue(any(f.anomaly_type == "IOC_MATCH" for f in f3))

        # nc.exe
        p4 = ProcessInfo(pid=2004, name="nc.exe")
        f4 = self.engine_win.analyze_process(p4)
        self.assertTrue(any(f.anomaly_type == "IOC_MATCH" for f in f4))

    def test_flag_double_extension(self):
        proc = ProcessInfo(pid=3001, name="Quarterly_Report.pdf.exe")
        findings = self.engine_win.analyze_process(proc)
        self.assertTrue(any(f.anomaly_type == "DOUBLE_EXTENSION" for f in findings))

    def test_flag_trailing_whitespace(self):
        proc = ProcessInfo(pid=3002, name="svchost.exe ")
        findings = self.engine_win.analyze_process(proc)
        self.assertTrue(any(f.anomaly_type == "TRAILING_DELIMITER_EVASION" for f in findings))

    def test_flag_unicode_homoglyphs(self):
        # Cyrillic 'а' (U+0430) inside "explorer.exe"
        cyrillic_name = "expl\u043erer.exe"
        proc = ProcessInfo(pid=3003, name=cyrillic_name)
        findings = self.engine_win.analyze_process(proc)
        self.assertTrue(any(f.anomaly_type == "UNICODE_HOMOGLYPH_INJECTION" for f in findings))

    def test_benign_software_not_flagged(self):
        benign_procs = [
            ProcessInfo(pid=4001, name="chrome.exe"),
            ProcessInfo(pid=4002, name="slack.exe"),
            ProcessInfo(pid=4003, name="code.exe"),
            ProcessInfo(pid=4004, name="python.exe"),
        ]
        for p in benign_procs:
            findings = self.engine_win.analyze_process(p)
            # Should have no anomaly findings
            self.assertEqual(len(findings), 0, f"False positive on {p.name}: {findings}")


if __name__ == "__main__":
    unittest.main()
