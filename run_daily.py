#!/usr/bin/env python3
"""Daily Host Hygiene Runner: Designed for scheduled daily execution on personal laptops.

- Automatically saves daily timestamped JSON reports to daily_reports/
- Maintains a historical CSV log (daily_reports/history.csv) for tracking trends
- Triggers a desktop alert if hygiene score drops or threats are detected
"""

import sys
import os
import csv
from datetime import datetime

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from host_hygiene.agent import HostHygieneAgent
from host_hygiene.reporter.console import ConsoleReporter
from host_hygiene.reporter.json_exporter import JSONExporter


def send_desktop_notification(title: str, message: str, is_warning: bool = False):
    """Show a native desktop notification across Windows, macOS, and Linux."""
    import subprocess
    clean_msg = message.replace('"', '\\"').replace("'", "")
    clean_title = title.replace('"', '\\"').replace("'", "")

    if sys.platform == "win32":
        try:
            icon_type = 48 if is_warning else 64  # 48=Warning, 64=Information in Windows Shell.Popup
            ps_script = f"""
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup('{clean_msg}', 5, '{clean_title}', {icon_type}) | Out-Null
            """
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            osa_script = f'display notification "{clean_msg}" with title "{clean_title}"'
            subprocess.run(
                ["/usr/bin/osascript", "-e", osa_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
    else:
        try:
            urgency = "critical" if is_warning else "normal"
            subprocess.run(
                ["notify-send", "-u", urgency, clean_title, clean_msg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass


# Retain backward compatibility
send_windows_notification = send_desktop_notification


def run_daily():
    reports_dir = os.path.join(SCRIPT_DIR, "daily_reports")
    os.makedirs(reports_dir, exist_ok=True)

    today_str = datetime.now().strftime("%Y-%m-%d")
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = os.path.join(reports_dir, f"hygiene_report_{today_str}.json")
    history_csv = os.path.join(reports_dir, "history.csv")

    # Check for API key in environment
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    force_offline = not bool(api_key and api_key.strip())

    agent = HostHygieneAgent(
        api_key=api_key,
        force_offline=force_offline,
    )

    ConsoleReporter.print_banner()
    print(f"[*] Executing Daily Host Hygiene Audit: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Mode: {'AI Triage (Gemini)' if not force_offline else 'Offline Rule-Based'}\n")

    report, anomalies_by_pid = agent.run_hygiene_assessment()
    ConsoleReporter.render_report(report, agent.platform_name, anomalies_by_pid)

    # 1. Export daily JSON report
    JSONExporter.export(
        report=report,
        platform_name=agent.platform_name,
        anomalies_by_pid=anomalies_by_pid,
        output_file=json_path,
    )
    print(f"[+] Daily report saved to: {json_path}")

    # 2. Append to history CSV for historical tracking
    file_exists = os.path.isfile(history_csv)
    with open(history_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "Timestamp",
                "Date",
                "Score",
                "OverallRisk",
                "TotalProcesses",
                "NoiseFiltered",
                "Candidates",
                "AnomaliesFlagged",
                "Mode",
            ])
        writer.writerow([
            timestamp_str,
            today_str,
            report.hygiene_score,
            report.overall_risk,
            report.total_inspected,
            report.noise_filtered_count,
            report.candidate_count,
            report.anomalies_detected_count,
            report.mode,
        ])
    print(f"[+] Appended entry to: {history_csv}")

    # 3. Notification alert on anomalies or low score
    if report.anomalies_detected_count > 0 or report.hygiene_score < 75:
        send_desktop_notification(
            title="Host Hygiene Alert!",
            message=f"Hygiene Score: {report.hygiene_score}/100. Flagged {report.anomalies_detected_count} suspicious process(es). Check daily_reports for details.",
            is_warning=True,
        )
    else:
        print("[+] Host hygiene is in good standing.")


if __name__ == "__main__":
    run_daily()
