"""Terminal console reporting with formatted tables and color-coded risk indicators."""

import sys
import os
from typing import List, Dict, Any, Optional

from ..triage.base import TriageReport, ProcessTriageEvaluation
from ..detector.anomaly_engine import AnomalyFinding


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass


def safe_str(val: Any) -> str:
    """Format string safely avoiding UnicodeEncodeError on cp1252/ascii Windows consoles."""
    s = str(val)
    encoding = sys.stdout.encoding or "utf-8"
    try:
        s.encode(encoding)
        return s
    except (UnicodeEncodeError, LookupError):
        out = []
        for ch in s:
            try:
                ch.encode(encoding)
                out.append(ch)
            except (UnicodeEncodeError, LookupError):
                out.append(f"\\u{ord(ch):04x}")
        return "".join(out)


class Color:
    """ANSI color codes with terminal detection."""
    _USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"

    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    RED = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELLOW = "\033[93m" if _USE_COLOR else ""
    BLUE = "\033[94m" if _USE_COLOR else ""
    MAGENTA = "\033[95m" if _USE_COLOR else ""
    CYAN = "\033[96m" if _USE_COLOR else ""
    WHITE = "\033[97m" if _USE_COLOR else ""


def risk_badge(risk: str) -> str:
    """Format risk rating with color badge."""
    r = risk.upper()
    if r == "MALICIOUS" or r == "CRITICAL":
        return f"{Color.RED}{Color.BOLD}[{r}]{Color.RESET}"
    elif r == "SUSPICIOUS" or r == "HIGH":
        return f"{Color.YELLOW}{Color.BOLD}[{r}]{Color.RESET}"
    elif r == "ELEVATED" or r == "MEDIUM":
        return f"{Color.MAGENTA}[{r}]{Color.RESET}"
    else:
        return f"{Color.GREEN}[{r}]{Color.RESET}"


def score_badge(score: int) -> str:
    """Format hygiene score with color."""
    if score >= 90:
        return f"{Color.GREEN}{Color.BOLD}{score}/100 (EXCELLENT){Color.RESET}"
    elif score >= 75:
        return f"{Color.CYAN}{Color.BOLD}{score}/100 (GOOD){Color.RESET}"
    elif score >= 50:
        return f"{Color.YELLOW}{Color.BOLD}{score}/100 (FAIR / SUSPICIOUS){Color.RESET}"
    else:
        return f"{Color.RED}{Color.BOLD}{score}/100 (CRITICAL RISKS DETECTED){Color.RESET}"


class ConsoleReporter:
    """Renders formatted CLI host hygiene reports."""

    @staticmethod
    def print_banner():
        banner = f"""{Color.CYAN}{Color.BOLD}
================================================================================
          HOST HYGIENE & ACTIVE PROCESS TRIAGE AGENT
================================================================================{Color.RESET}"""
        print(banner)

    @staticmethod
    def render_report(
        report: TriageReport,
        platform_name: str,
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
    ):
        """Print full structured triage report to console."""
        print()
        print(f"{Color.BOLD}--- HOST HYGIENE SUMMARY ---{Color.RESET}")
        print(f"  Operating System:        {platform_name.upper()}")
        print(f"  Triage Mode:             {report.mode.upper()} {f'({report.model_used})' if report.model_used else ''}")
        print(f"  Total Processes Seen:    {report.total_inspected}")
        filter_pct = (
            (report.noise_filtered_count / report.total_inspected * 100)
            if report.total_inspected > 0
            else 0.0
        )
        print(f"  OS Baseline Noise Filter:{report.noise_filtered_count} processes filtered ({filter_pct:.1f}% reduction)")
        print(f"  Unclassified Candidates: {report.candidate_count}")
        print(f"  Anomalies Flagged:       {report.anomalies_detected_count}")
        print(f"  Overall Host Risk:       {risk_badge(report.overall_risk)}")
        print(f"  Daily Hygiene Score:     {score_badge(report.hygiene_score)}")
        print()
        print(f"{Color.BOLD}  Summary:{Color.RESET} {report.summary}")
        print()

        # Section: Anomaly Findings
        all_findings: List[AnomalyFinding] = []
        for findings in anomalies_by_pid.values():
            all_findings.extend(findings)

        if all_findings:
            print(f"{Color.BOLD}{Color.YELLOW}--- DETECTED ANOMALIES & SUSPICIOUS NAMING PATTERNS ({len(all_findings)}) ---{Color.RESET}")
            # Header
            print(f"  {'PID':<7} {'PROCESS':<22} {'SEVERITY':<12} {'TYPE':<25} {'DESCRIPTION'}")
            print(f"  {'-'*6} {'-'*20} {'-'*10} {'-'*23} {'-'*30}")
            for f in sorted(all_findings, key=lambda x: (0 if x.severity == 'CRITICAL' else 1 if x.severity == 'HIGH' else 2)):
                sev_fmt = risk_badge(f.severity)
                safe_name = safe_str(f.process_name)[:20]
                safe_desc = safe_str(f.description)
                print(f"  {f.process_pid:<7} {safe_name:<22} {sev_fmt:<20} {f.anomaly_type[:23]:<25} {safe_desc}")
            print()

        # Section: Persistence & Autostart Findings
        if report.persistence_findings:
            suspicious_persist = [p for p in report.persistence_findings if p.get("is_user_writable")]
            print(f"{Color.BOLD}--- PERSISTENCE & AUTOSTART AUDIT ({len(report.persistence_findings)} items scanned) ---{Color.RESET}")
            if suspicious_persist:
                print(f"  {Color.YELLOW}{Color.BOLD}WARNING: Detected {len(suspicious_persist)} autostart item(s) targeting user-writable or suspicious locations:{Color.RESET}")
                for sp in suspicious_persist:
                    loc = sp.get("location", "Registry/Startup")
                    name = sp.get("name", "Unknown")
                    target = sp.get("target", "")
                    print(f"    * {Color.YELLOW}[{loc}]{Color.RESET} {Color.BOLD}{name}{Color.RESET} -> {target}")
            else:
                print(f"  {Color.GREEN}[+] All autostart entries point to protected system/program directories.{Color.RESET}")
            print()

        # Section: Process Triage Details
        print(f"{Color.BOLD}--- UNCLASSIFIED / CANDIDATE PROCESS TRIAGE ({len(report.evaluated_processes)}) ---{Color.RESET}")
        if not report.evaluated_processes:
            print(f"  {Color.DIM}No candidate processes outside the OS baseline.{Color.RESET}")
        else:
            for p in report.evaluated_processes:
                badge = risk_badge(p.risk_rating)
                safe_pname = safe_str(p.process_name)
                class_tag = f" [{p.classification}]" if p.classification else ""
                print(f"  * {Color.BOLD}PID {p.pid:<6}{Color.RESET} {Color.CYAN}{safe_pname}{Color.RESET}{Color.DIM}{class_tag}{Color.RESET} -> {badge}")
                if p.path:
                    print(f"    {Color.DIM}Path:{Color.RESET}      {safe_str(p.path)}")
                if p.parent and p.parent.get("name") != "unknown":
                    print(f"    {Color.DIM}Parent:{Color.RESET}    {p.parent.get('name')} (PID {p.parent.get('pid')})")
                if p.user:
                    print(f"    {Color.DIM}User:{Color.RESET}      {safe_str(p.user)}")
                if p.signature and p.signature.get("status"):
                    sig_stat = p.signature.get("status")
                    sig_pub = p.signature.get("publisher") or "Unsigned"
                    print(f"    {Color.DIM}Signature:{Color.RESET} {sig_stat} ({safe_str(sig_pub)[:45]})")
                if p.sha256:
                    print(f"    {Color.DIM}SHA256:{Color.RESET}    {p.sha256[:16]}...")
                if p.network_connections:
                    ports = [f"{c.get('type')}:{c.get('local_port')}" for c in p.network_connections[:3]]
                    print(f"    {Color.DIM}Sockets:{Color.RESET}   {', '.join(ports)}")
                print(f"    {Color.DIM}Purpose:{Color.RESET}   {safe_str(p.purpose)}")
                if p.reasoning:
                    print(f"    {Color.DIM}Reasoning:{Color.RESET} {safe_str(p.reasoning)}")
                if p.actionable_recommendations:
                    for rec in p.actionable_recommendations:
                        print(f"    {Color.YELLOW}-> Rec:{Color.RESET}     {safe_str(rec)}")
                print()

        # Section: Actionable Host Recommendations
        if report.host_recommendations:
            print(f"{Color.BOLD}{Color.GREEN}--- ACTIONABLE HOST RECOMMENDATIONS ---{Color.RESET}")
            for idx, rec in enumerate(report.host_recommendations, 1):
                print(f"  {idx}. {rec}")
            print()

        print(f"{Color.CYAN}{'='*80}{Color.RESET}")
