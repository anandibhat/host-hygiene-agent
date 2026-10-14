"""Windows Process Collector with Enriched Forensic Telemetry.

Extracts executable path, parent process lineage, command-line arguments,
code signing verification, SHA-256 hash, and active network connections.
"""

import sys
import os
import ctypes
from ctypes import wintypes
import hashlib
import json
import subprocess
from typing import List, Optional, Dict, Any

from .base import BaseProcessCollector, ProcessInfo
from .network import NetworkTelemetryCollector
from .signature import SignatureVerifier
from ..baseline.cache import BaselineCache

# Windows API Constants
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1


class PROCESSENTRY32W(ctypes.Structure):
    """Structure representing a process entry in a snapshot."""
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class WindowsProcessCollector(BaseProcessCollector):
    """Collects running processes on Windows with enriched forensic telemetry."""

    def __init__(self, cache: Optional[BaselineCache] = None):
        self._kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
        self._advapi32 = ctypes.windll.advapi32 if sys.platform == "win32" else None
        self.cache = cache
        self.sig_verifier = SignatureVerifier(cache=cache)

    def get_platform_name(self) -> str:
        return "windows"

    def _get_process_path(self, pid: int) -> Optional[str]:
        """Attempt to retrieve executable path using QueryFullProcessImageNameW."""
        if not self._kernel32 or pid in (0, 4):
            return None

        h_process = self._kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not h_process:
            h_process = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION, False, pid
            )
        if not h_process:
            return None

        try:
            buf_len = wintypes.DWORD(1024)
            buf = ctypes.create_unicode_buffer(buf_len.value)
            if hasattr(self._kernel32, "QueryFullProcessImageNameW"):
                if self._kernel32.QueryFullProcessImageNameW(
                    h_process, 0, buf, ctypes.byref(buf_len)
                ):
                    return buf.value
            return None
        except Exception:
            return None
        finally:
            self._kernel32.CloseHandle(h_process)

    def _get_process_user(self, pid: int) -> Optional[str]:
        """Extract user / domain running the process via token lookup."""
        if pid in (0, 4):
            return r"NT AUTHORITY\SYSTEM"
        if not self._kernel32 or not self._advapi32:
            return None

        h_proc = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_proc:
            return None

        h_token = wintypes.HANDLE()
        user_str = None
        try:
            if self._advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, ctypes.byref(h_token)):
                ret_len = wintypes.DWORD()
                self._advapi32.GetTokenInformation(h_token, TOKEN_USER_CLASS, None, 0, ctypes.byref(ret_len))
                if ret_len.value > 0:
                    buf = ctypes.create_string_buffer(ret_len.value)
                    if self._advapi32.GetTokenInformation(h_token, TOKEN_USER_CLASS, buf, ret_len.value, ctypes.byref(ret_len)):
                        sid_ptr = ctypes.c_void_p.from_buffer_copy(buf.raw[:ctypes.sizeof(ctypes.c_void_p)]).value
                        if sid_ptr:
                            name_len = wintypes.DWORD(256)
                            name = ctypes.create_unicode_buffer(name_len.value)
                            domain_len = wintypes.DWORD(256)
                            domain = ctypes.create_unicode_buffer(domain_len.value)
                            sid_type = wintypes.DWORD()
                            if self._advapi32.LookupAccountSidW(
                                None, ctypes.c_void_p(sid_ptr), name, ctypes.byref(name_len),
                                domain, ctypes.byref(domain_len), ctypes.byref(sid_type)
                            ):
                                user_str = f"{domain.value}\\{name.value}" if domain.value else name.value
                self._kernel32.CloseHandle(h_token)
        except Exception:
            pass
        finally:
            self._kernel32.CloseHandle(h_proc)
        return user_str

    @staticmethod
    def _compute_sha256(filepath: Optional[str]) -> Optional[str]:
        """Calculate SHA-256 cryptographic hash of executable."""
        if not filepath or not os.path.isfile(filepath):
            return None
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    @staticmethod
    def _get_batch_command_lines() -> Dict[int, str]:
        """Batch-query command lines for all processes via Win32_Process."""
        cmd_map: Dict[int, str] = {}
        if sys.platform != "win32":
            return cmd_map
        try:
            ps_cmd = "Get-CimInstance Win32_Process -Property ProcessId, CommandLine | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    pid = item.get("ProcessId")
                    cmdline = item.get("CommandLine")
                    if pid is not None and cmdline:
                        cmd_map[pid] = cmdline
        except Exception:
            pass
        return cmd_map

    def collect(self) -> List[ProcessInfo]:
        """Collect processes with complete enriched telemetry."""
        if not self._kernel32:
            return self._fallback_tasklist()

        raw_entries = []
        pid_to_name: Dict[int, str] = {0: "[System Process]", 4: "System"}

        h_snapshot = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snapshot == INVALID_HANDLE_VALUE or not h_snapshot:
            return self._fallback_tasklist()

        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

            has_next = self._kernel32.Process32FirstW(h_snapshot, ctypes.byref(entry))
            while has_next:
                pid = int(entry.th32ProcessID)
                ppid = int(entry.th32ParentProcessID)
                name = str(entry.szExeFile)
                pid_to_name[pid] = name
                raw_entries.append((pid, ppid, name))
                has_next = self._kernel32.Process32NextW(h_snapshot, ctypes.byref(entry))
        finally:
            self._kernel32.CloseHandle(h_snapshot)

        # 1. Retrieve network connections correlated to PID
        net_conns = NetworkTelemetryCollector.collect_connections()

        # 2. Retrieve command-line arguments in batch
        cmdline_map = self._get_batch_command_lines()

        # 3. Collect paths, users, hashes, and files to verify
        paths_to_verify: List[str] = []
        temp_data = []
        sha_cache: Dict[str, Optional[str]] = {}
        for pid, ppid, name in raw_entries:
            path = self._get_process_path(pid)
            user = self._get_process_user(pid)
            sha256 = None
            if path:
                if path in sha_cache:
                    sha256 = sha_cache[path]
                else:
                    sha256 = self._compute_sha256(path)
                    sha_cache[path] = sha256
            cmdline = cmdline_map.get(pid)

            if path and os.path.isfile(path):
                paths_to_verify.append(path)

            temp_data.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "path": path,
                "user": user,
                "sha256": sha256,
                "cmdline": cmdline,
            })

        # 4. Verify code signatures (deduplicated unique paths)
        unique_paths = list(dict.fromkeys(paths_to_verify))
        sig_map = self.sig_verifier.verify_batch(unique_paths)

        # 5. Build enriched ProcessInfo objects
        processes: List[ProcessInfo] = []
        for item in temp_data:
            pid = item["pid"]
            ppid = item["ppid"]
            name = item["name"]
            path = item["path"]
            user = item["user"]
            sha256 = item["sha256"]
            cmdline = item["cmdline"]

            parent_info = {
                "pid": ppid,
                "name": pid_to_name.get(ppid, "unknown"),
            }

            sig = sig_map.get(path, {"status": "UNVERIFIED", "publisher": ""})
            conns = net_conns.get(pid, [])

            # Update cache if valid signature found
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
            self.cache.save()

        return processes

    def _fallback_tasklist(self) -> List[ProcessInfo]:
        """Tasklist fallback if toolhelp snapshot is unavailable."""
        import csv
        import io

        processes: List[ProcessInfo] = []
        try:
            output = subprocess.check_output(
                ["tasklist.exe", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            )
            reader = csv.reader(io.StringIO(output))
            for row in reader:
                if len(row) >= 2:
                    name = row[0].strip('"')
                    try:
                        pid = int(row[1].strip('"'))
                    except ValueError:
                        continue
                    processes.append(
                        ProcessInfo(
                            pid=pid,
                            name=name,
                            parent={"pid": 0, "name": "unknown"},
                            signature={"status": "UNVERIFIED", "publisher": ""},
                        )
                    )
        except Exception:
            pass
        return processes
