"""Linux Process Collector using pure Python standard library (/proc filesystem).

Inspects active running processes (PID, process name, command line, and executable path)
without requiring external binary dependencies (no ps, no pgrep, no psutil).
"""

import os
from typing import List, Optional

from .base import BaseProcessCollector, ProcessInfo


class LinuxProcessCollector(BaseProcessCollector):
    """Collects running processes on Linux by directly parsing the /proc filesystem."""

    def __init__(self, proc_path: str = "/proc"):
        self.proc_path = proc_path

    def get_platform_name(self) -> str:
        return "linux"

    def collect(self) -> List[ProcessInfo]:
        """Iterate over /proc numeric directories and parse process metadata."""
        processes: List[ProcessInfo] = []

        if not os.path.exists(self.proc_path):
            return processes

        try:
            entries = os.listdir(self.proc_path)
        except (PermissionError, FileNotFoundError):
            return processes

        for entry in entries:
            if not entry.isdigit():
                continue

            pid = int(entry)
            pid_dir = os.path.join(self.proc_path, entry)

            try:
                # 1. Process name from /proc/[pid]/comm
                name = self._read_comm(pid_dir)
                if not name:
                    # Fallback to /proc/[pid]/cmdline or stat
                    name = self._read_name_from_stat_or_cmdline(pid_dir, pid)
                if not name:
                    name = f"proc_{pid}"

                # 2. Executable path via /proc/[pid]/exe
                path = self._read_exe_symlink(pid_dir)

                # 3. Command line from /proc/[pid]/cmdline
                cmdline = self._read_cmdline(pid_dir)

                # 4. PPID from /proc/[pid]/stat or /proc/[pid]/status
                ppid = self._read_ppid(pid_dir)

                processes.append(
                    ProcessInfo(
                        pid=pid,
                        name=name,
                        path=path,
                        command_line=cmdline,
                        parent={"pid": ppid, "name": "unknown"},
                    )
                )
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                # Process terminated or disappeared during scan
                continue

        return processes

    def _read_comm(self, pid_dir: str) -> Optional[str]:
        comm_file = os.path.join(pid_dir, "comm")
        try:
            with open(comm_file, "r", encoding="utf-8", errors="replace") as f:
                val = f.read().strip()
                return val if val else None
        except Exception:
            return None

    def _read_exe_symlink(self, pid_dir: str) -> Optional[str]:
        exe_file = os.path.join(pid_dir, "exe")
        try:
            return os.readlink(exe_file)
        except Exception:
            return None

    def _read_cmdline(self, pid_dir: str) -> Optional[str]:
        cmdline_file = os.path.join(pid_dir, "cmdline")
        try:
            with open(cmdline_file, "rb") as f:
                content = f.read()
                if not content:
                    return None
                parts = content.split(b"\x00")
                non_empty = [p.decode("utf-8", errors="replace") for p in parts if p]
                return " ".join(non_empty) if non_empty else None
        except Exception:
            return None

    def _read_ppid(self, pid_dir: str) -> Optional[int]:
        status_file = os.path.join(pid_dir, "status")
        try:
            with open(status_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            return int(parts[1].strip())
        except Exception:
            pass
        return None

    def _read_name_from_stat_or_cmdline(self, pid_dir: str, pid: int) -> Optional[str]:
        # stat file format: pid (name) state ppid ...
        stat_file = os.path.join(pid_dir, "stat")
        try:
            with open(stat_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                start = content.find("(")
                end = content.rfind(")")
                if start != -1 and end != -1 and end > start:
                    return content[start + 1:end]
        except Exception:
            pass
        return None
