"""Linux Process Collector using pure Python standard library (/proc filesystem).

Inspects active running processes (PID, process name, command line, executable path,
parent lineage, user, SHA-256 hash, and network sockets) without requiring external binary dependencies.
"""

from __future__ import annotations
import os
import hashlib
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from .base import BaseProcessCollector, ProcessInfo
from .network import NetworkTelemetryCollector
from .signature import SignatureVerifier
if TYPE_CHECKING:
    from ..baseline.cache import BaselineCache


class LinuxProcessCollector(BaseProcessCollector):
    """Collects running processes on Linux by directly parsing the /proc filesystem with enriched telemetry."""

    def __init__(self, proc_path: str = "/proc", cache: Optional[BaselineCache] = None):
        self.proc_path = proc_path
        self.cache = cache
        self.sig_verifier = SignatureVerifier(cache=cache)

    def get_platform_name(self) -> str:
        return "linux"

    def _compute_sha256(self, file_path: str) -> Optional[str]:
        if not file_path or not os.path.isfile(file_path):
            return None
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def collect(self) -> List[ProcessInfo]:
        """Iterate over /proc numeric directories and parse process metadata with enriched telemetry."""
        if not os.path.exists(self.proc_path):
            return []

        try:
            entries = os.listdir(self.proc_path)
        except (PermissionError, FileNotFoundError):
            return []

        # 1. Retrieve active socket connections mapped by PID
        net_conns = NetworkTelemetryCollector.collect_connections()

        raw_entries = []
        pid_to_name: Dict[int, str] = {}
        paths_to_verify: List[str] = []

        for entry in entries:
            if not entry.isdigit():
                continue

            pid = int(entry)
            pid_dir = os.path.join(self.proc_path, entry)

            try:
                # 1. Process name from /proc/[pid]/comm
                name = self._read_comm(pid_dir)
                if not name:
                    name = self._read_name_from_stat_or_cmdline(pid_dir, pid)
                if not name:
                    name = f"proc_{pid}"

                # 2. Executable path via /proc/[pid]/exe
                path = self._read_exe_symlink(pid_dir)

                # 3. Command line from /proc/[pid]/cmdline
                cmdline = self._read_cmdline(pid_dir)

                # 4. PPID from /proc/[pid]/status
                ppid = self._read_ppid(pid_dir) or 1

                # 5. User from /proc/[pid]/status
                user = self._read_user(pid_dir)

                pid_to_name[pid] = name
                if path and os.path.isfile(path):
                    paths_to_verify.append(path)

                raw_entries.append({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "path": path,
                    "user": user,
                    "cmdline": cmdline,
                })
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue

        # Deduplicate paths and query signatures
        unique_paths = list(dict.fromkeys(paths_to_verify))
        sig_map = self.sig_verifier.verify_batch(unique_paths)

        processes: List[ProcessInfo] = []
        sha_cache: Dict[str, Optional[str]] = {}

        for item in raw_entries:
            pid = item["pid"]
            ppid = item["ppid"]
            name = item["name"]
            path = item["path"]
            user = item["user"]
            cmdline = item["cmdline"]

            parent_info = {
                "pid": ppid,
                "name": pid_to_name.get(ppid, "unknown"),
            }

            sha256 = None
            if path:
                if path in sha_cache:
                    sha256 = sha_cache[path]
                else:
                    sha256 = self._compute_sha256(path)
                    sha_cache[path] = sha256

            sig = sig_map.get(path, {"status": "UNVERIFIED", "publisher": ""})
            conns = net_conns.get(pid, [])

            if self.cache and path and sha256 and sig.get("status") == "VALID":
                self.cache.set(path, sha256, sig)

            processes.append(
                ProcessInfo(
                    pid=pid,
                    name=name,
                    path=path,
                    command_line=cmdline,
                    parent=parent_info,
                    user=user,
                    sha256=sha256,
                    signature=sig,
                    network_connections=conns,
                )
            )

        if self.cache:
            try:
                self.cache.save()
            except Exception:
                pass

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

    def _read_user(self, pid_dir: str) -> Optional[str]:
        status_file = os.path.join(pid_dir, "status")
        try:
            with open(status_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            uid = parts[1]
                            try:
                                import pwd
                                return pwd.getpwuid(int(uid)).pw_name
                            except Exception:
                                return uid
        except Exception:
            pass
        return None

    def _read_name_from_stat_or_cmdline(self, pid_dir: str, pid: int) -> Optional[str]:
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
