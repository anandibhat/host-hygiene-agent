#!/usr/bin/env python3
"""Interactive demo script that simulates realistic endpoint workloads with threats and benign processes."""

import argparse
import sys
from host_hygiene.agent import HostHygieneAgent
from host_hygiene.collector.base import ProcessInfo
from host_hygiene.reporter.console import ConsoleReporter
from host_hygiene.reporter.json_exporter import JSONExporter


def get_simulated_workload(platform: str = "windows") -> list[ProcessInfo]:
    """Generates a realistic test battery of processes across categories."""
    if platform == "windows":
        return [
            # Standard OS noise (to be filtered out)
            ProcessInfo(pid=4, name="System"),
            ProcessInfo(pid=812, name="smss.exe"),
            ProcessInfo(pid=944, name="csrss.exe"),
            ProcessInfo(pid=1020, name="wininit.exe"),
            ProcessInfo(pid=1088, name="services.exe"),
            ProcessInfo(pid=1124, name="lsass.exe"),
            ProcessInfo(pid=1204, name="svchost.exe"),
            ProcessInfo(pid=1356, name="svchost.exe"),
            ProcessInfo(pid=1420, name="fontdrvhost.exe"),
            ProcessInfo(pid=1588, name="dwm.exe"),
            ProcessInfo(pid=2104, name="explorer.exe"),
            ProcessInfo(pid=2240, name="RuntimeBroker.exe"),
            # Benign user / developer applications
            ProcessInfo(pid=5012, name="chrome.exe"),
            ProcessInfo(pid=5016, name="chrome.exe"),
            ProcessInfo(pid=6120, name="code.exe"),
            ProcessInfo(pid=7420, name="python.exe"),
            ProcessInfo(pid=8104, name="slack.exe"),
            # Suspicious & Malicious threats
            ProcessInfo(pid=9001, name="svch0st.exe"),                      # Typosquatting (0 -> o)
            ProcessInfo(pid=9002, name="mimikatz.exe"),                     # Known IOC (Credential dumper)
            ProcessInfo(pid=9003, name="Q3_Financial_Summary.pdf.exe"),     # Double extension deception
            ProcessInfo(pid=9004, name="xmrig.exe"),                        # Cryptominer
            ProcessInfo(pid=9005, name="svchost32.exe"),                    # Masquerading suffix
            ProcessInfo(pid=9006, name="expl\u043erer.exe"),                # Cyrillic Unicode homoglyph injection
            ProcessInfo(pid=9007, name="nc.exe"),                           # Netcat reverse shell tool
        ]
    elif platform == "linux":
        return [
            # Standard OS noise
            ProcessInfo(pid=1, name="systemd"),
            ProcessInfo(pid=2, name="kthreadd"),
            ProcessInfo(pid=14, name="kworker/0:1-events"),
            ProcessInfo(pid=405, name="systemd-journald"),
            ProcessInfo(pid=430, name="systemd-udevd"),
            ProcessInfo(pid=610, name="cron"),
            ProcessInfo(pid=625, name="sshd"),
            ProcessInfo(pid=630, name="dbus-daemon"),
            # Benign software
            ProcessInfo(pid=1200, name="bash"),
            ProcessInfo(pid=1350, name="python3"),
            ProcessInfo(pid=1420, name="dockerd"),
            # Threats
            ProcessInfo(pid=8801, name="systemdd"),                          # Typosquatting systemd
            ProcessInfo(pid=8802, name="xmrig"),                            # Cryptominer
            ProcessInfo(pid=8803, name="linpeas"),                          # Privesc tool
            ProcessInfo(pid=8804, name="win_payload.exe"),                  # Windows executable on Linux
            ProcessInfo(pid=8805, name="chisel"),                           # Tunneling tool
        ]
    else:  # darwin
        return [
            # Standard OS noise
            ProcessInfo(pid=1, name="launchd"),
            ProcessInfo(pid=120, name="WindowServer"),
            ProcessInfo(pid=150, name="loginwindow"),
            ProcessInfo(pid=210, name="cfprefsd"),
            ProcessInfo(pid=220, name="distnoted"),
            ProcessInfo(pid=305, name="Finder"),
            ProcessInfo(pid=310, name="Dock"),
            # Benign software
            ProcessInfo(pid=1100, name="zsh"),
            ProcessInfo(pid=1250, name="safari"),
            # Threats
            ProcessInfo(pid=7701, name="1aunchd"),                          # Typosquatting launchd (1 -> l)
            ProcessInfo(pid=7702, name="sliver"),                           # C2 framework
            ProcessInfo(pid=7703, name="payload.pdf.exe"),                  # Double extension
        ]


def main():
    parser = argparse.ArgumentParser(
        description="Run Host Hygiene Triage against a simulated test battery."
    )
    parser.add_argument(
        "--platform",
        choices=["windows", "linux", "darwin"],
        default="windows",
        help="Simulated operating system (default: windows)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        default=True,
        help="Run in offline rule-based fallback mode (default: True)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Use Gemini LLM API (reads GEMINI_API_KEY environment variable)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Gemini API Key for AI triage mode",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Export simulation report to JSON file",
    )

    args = parser.parse_args()

    use_offline = not args.ai
    agent = HostHygieneAgent(
        platform_override=args.platform,
        api_key=args.api_key,
        force_offline=use_offline,
    )

    mock_procs = get_simulated_workload(args.platform)

    ConsoleReporter.print_banner()
    print(f"\n[*] Running simulated inspection of {len(mock_procs)} processes on {args.platform.upper()}...")
    report, anomalies_by_pid = agent.run_hygiene_assessment(mock_processes=mock_procs)
    ConsoleReporter.render_report(report, args.platform, anomalies_by_pid)

    if args.json_out:
        JSONExporter.export(report, args.platform, anomalies_by_pid, args.json_out)
        print(f"Simulation report written to {args.json_out}")


if __name__ == "__main__":
    main()
