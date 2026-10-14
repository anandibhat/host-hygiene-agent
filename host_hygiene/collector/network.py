"""Network Telemetry: Correlates processes with listening ports and outbound connections."""

import sys
import subprocess
import re
from typing import Dict, List, Any

# Common suspicious remote or listening ports used by malware and offensive tools
SUSPICIOUS_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Elite Backdoor Port",
    6667: "IRC Botnet C2",
    8888: "Generic Proxy / C2",
    31337: "Back Orifice / Trojan Port",
    5555: "Android ADB / Trojan",
    7000: "FRP Proxy Port",
    7500: "FRP Dashboard",
}


class NetworkTelemetryCollector:
    """Collects socket connections and correlates them with Process IDs."""

    @staticmethod
    def collect_connections() -> Dict[int, List[Dict[str, Any]]]:
        """Collects network connections mapped by PID."""
        if sys.platform == "win32":
            return NetworkTelemetryCollector._collect_windows()
        elif sys.platform == "linux":
            return NetworkTelemetryCollector._collect_linux()
        return {}

    @staticmethod
    def _collect_windows() -> Dict[int, List[Dict[str, Any]]]:
        pid_map: Dict[int, List[Dict[str, Any]]] = {}
        try:
            proc = subprocess.run(
                ["netstat.exe", "-ano"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Regex to match netstat output:
            # TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1308
            pattern = re.compile(
                r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+([A-Z_]+))?\s+(\d+)\s*$",
                re.MULTILINE,
            )
            for match in pattern.finditer(proc.stdout):
                proto = match.group(1)
                local = match.group(2)
                remote = match.group(3)
                state = match.group(4) or ("LISTENING" if proto == "UDP" else "UNKNOWN")
                pid = int(match.group(5))

                l_ip, l_port = local.rsplit(":", 1) if ":" in local else (local, "0")
                r_ip, r_port = remote.rsplit(":", 1) if ":" in remote else (remote, "0")

                conn_type = (
                    "LISTEN"
                    if state in ("LISTENING", "LISTEN")
                    else ("ESTABLISHED" if state == "ESTABLISHED" else state)
                )

                conn_obj = {
                    "type": conn_type,
                    "proto": proto,
                    "local_address": l_ip.strip("[]"),
                    "local_port": int(l_port) if l_port.isdigit() else 0,
                    "remote_address": r_ip.strip("[]"),
                    "remote_port": int(r_port) if r_port.isdigit() else 0,
                }

                if pid not in pid_map:
                    pid_map[pid] = []
                pid_map[pid].append(conn_obj)
        except Exception:
            pass
        return pid_map

    @staticmethod
    def _collect_linux() -> Dict[int, List[Dict[str, Any]]]:
        """Parse Linux /proc/net/tcp and ss if available."""
        pid_map: Dict[int, List[Dict[str, Any]]] = {}
        try:
            proc = subprocess.run(
                ["ss", "-tulpn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in proc.stdout.splitlines():
                if "pid=" in line:
                    match = re.search(r"pid=(\d+)", line)
                    if match:
                        pid = int(match.group(1))
                        conn_type = "LISTEN" if "LISTEN" in line else "ESTABLISHED"
                        if pid not in pid_map:
                            pid_map[pid] = []
                        pid_map[pid].append({"type": conn_type, "raw": line.strip()})
        except Exception:
            pass
        return pid_map
