"""macOS (Darwin) Process Collector using ctypes (libproc) with enriched forensic telemetry.

Inspects active running processes (PID, process name, executable path, parent lineage,
command line, user, code signing status, SHA-256 hash, and network connections)
without requiring external binary packages (e.g., psutil).
"""

from __future__ import annotations
import sys
import os
import ctypes
import hashlib
import subprocess
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from .base import BaseProcessCollector, ProcessInfo
from .network import NetworkTelemetryCollector
from .signature import SignatureVerifier
if TYPE_CHECKING:
    from ..baseline.cache import BaselineCache

# Constants for macOS libproc
PROC_PIDPATHINFO_MAXSIZE = 4096
PROC_ALL_PIDS = 1


class DarwinProcessCollector(BaseProcessCollector):
    """Collects running processes on macOS via libproc ctypes and POSIX introspection with enriched telemetry."""

    def __init__(self, cache: Optional[BaselineCache] = None):
        self.cache = cache
        self.sig_verifier = SignatureVerifier(cache=cache)
        self._libproc = None
        if sys.platform == "darwin":
            try:
                self._libproc = ctypes.CDLL("libproc.dylib")
            except Exception:
                try:
                    self._libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
                except Exception:
                    self._libproc = None

    def get_platform_name(self) -> str:
        return "darwin"

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

    def _get_ps_metadata(self) -> Dict[int, Dict[str, Any]]:
        """Extract ppid, user, and command-line arguments using POSIX ps."""
        meta: Dict[int, Dict[str, Any]] = {}
        try:
            output = subprocess.check_output(
                ["/bin/ps", "-ax", "-o", "pid,ppid,user,command"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            )
            for line in output.strip().splitlines()[1:]:
                parts = line.strip().split(None, 3)
                if len(parts) >= 3:
                    try:
                        pid = int(parts[0])
                        ppid = int(parts[1])
                        user = parts[2]
                        cmd = parts[3] if len(parts) >= 4 else ""
                        meta[pid] = {
                            "ppid": ppid,
                            "user": user,
                            "command_line": cmd,
                        }
                    except ValueError:
                        continue
        except Exception:
            pass
        return meta

    def collect(self) -> List[ProcessInfo]:
        """Collect running processes on macOS with enriched telemetry."""
        # 1. Retrieve supplementary metadata (ppid, user, cmdline)
        ps_meta = self._get_ps_metadata()

        # 2. Retrieve active socket connections mapped by PID
        net_conns = NetworkTelemetryCollector.collect_connections()

        # 3. Collect processes via libproc (or fallback to ps)
        raw_procs = self._collect_raw_procs(ps_meta)

        # 4. Map PIDs to names for accurate parent resolution
        pid_to_name: Dict[int, str] = {p["pid"]: p["name"] for p in raw_procs}

        # 5. Deduplicate executable paths for signature verification
        paths_to_verify = list(dict.fromkeys(
            p["path"] for p in raw_procs if p["path"] and os.path.isfile(p["path"])
        ))
        sig_map = self.sig_verifier.verify_batch(paths_to_verify)

        # 6. Build enriched ProcessInfo objects
        processes: List[ProcessInfo] = []
        sha_cache: Dict[str, Optional[str]] = {}

        for item in raw_procs:
            pid = item["pid"]
            name = item["name"]
            path = item["path"]
            ppid = item["ppid"]
            user = item["user"]
            cmdline = item["command_line"]

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

    def _collect_raw_procs(self, ps_meta: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collect PID, name, and executable path using libproc or ps."""
        if not self._libproc:
            return self._collect_raw_via_ps(ps_meta)

        try:
            self._libproc.proc_listpids.argtypes = [
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            self._libproc.proc_listpids.restype = ctypes.c_int

            buf_size = self._libproc.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
            if buf_size <= 0:
                return self._collect_raw_via_ps(ps_meta)

            num_pids = buf_size // ctypes.sizeof(ctypes.c_int)
            pid_array_type = ctypes.c_int * num_pids
            pids = pid_array_type()

            bytes_written = self._libproc.proc_listpids(
                PROC_ALL_PIDS, 0, ctypes.byref(pids), buf_size
            )
            if bytes_written <= 0:
                return self._collect_raw_via_ps(ps_meta)

            actual_count = bytes_written // ctypes.sizeof(ctypes.c_int)
            name_buf = ctypes.create_string_buffer(1024)
            path_buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)

            raw: List[Dict[str, Any]] = []
            for i in range(actual_count):
                pid = pids[i]
                if pid <= 0:
                    continue

                name = None
                path = None

                try:
                    ret_path = self._libproc.proc_pidpath(pid, path_buf, PROC_PIDPATHINFO_MAXSIZE)
                    if ret_path > 0:
                        path = path_buf.value.decode("utf-8", errors="replace")
                        name = os.path.basename(path)
                except Exception:
                    pass

                if not name:
                    try:
                        ret_name = self._libproc.proc_name(pid, name_buf, 1024)
                        if ret_name > 0:
                            name = name_buf.value.decode("utf-8", errors="replace")
                    except Exception:
                        pass

                p_info = ps_meta.get(pid, {})
                if not name and p_info.get("command_line"):
                    first_token = p_info["command_line"].split()[0]
                    name = os.path.basename(first_token)

                if not name:
                    name = f"proc_{pid}"

                raw.append({
                    "pid": pid,
                    "name": name,
                    "path": path,
                    "ppid": p_info.get("ppid", 1),
                    "user": p_info.get("user"),
                    "command_line": p_info.get("command_line"),
                })
            return raw
        except Exception:
            return self._collect_raw_via_ps(ps_meta)

    def _collect_raw_via_ps(self, ps_meta: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        raw: List[Dict[str, Any]] = []
        for pid, info in ps_meta.items():
            cmd = info.get("command_line") or ""
            name = os.path.basename(cmd.split()[0]) if cmd else f"proc_{pid}"
            path = cmd.split()[0] if cmd and os.path.isfile(cmd.split()[0]) else None
            raw.append({
                "pid": pid,
                "name": name,
                "path": path,
                "ppid": info.get("ppid", 1),
                "user": info.get("user"),
                "command_line": cmd,
            })
        return raw
