"""macOS (Darwin) Process Collector using ctypes (libproc) with standard OS fallback.

Inspects active running processes (PID, process name, and executable path)
without requiring external binary packages (e.g., psutil).
"""

import sys
import os
import ctypes
from typing import List, Optional

from .base import BaseProcessCollector, ProcessInfo

# Constants for macOS libproc
PROC_PIDPATHINFO_MAXSIZE = 4096
PROC_ALL_PIDS = 1


class DarwinProcessCollector(BaseProcessCollector):
    """Collects running processes on macOS via libproc ctypes or POSIX baseline."""

    def __init__(self):
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

    def collect(self) -> List[ProcessInfo]:
        """Collect running processes on macOS."""
        if self._libproc:
            try:
                return self._collect_via_libproc()
            except Exception:
                pass
        return self._collect_via_posix_ps()

    def _collect_via_libproc(self) -> List[ProcessInfo]:
        processes: List[ProcessInfo] = []

        # 1. Get number of PIDs
        # proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize)
        self._libproc.proc_listpids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self._libproc.proc_listpids.restype = ctypes.c_int

        buf_size = self._libproc.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
        if buf_size <= 0:
            return self._collect_via_posix_ps()

        num_pids = buf_size // ctypes.sizeof(ctypes.c_int)
        pid_array_type = ctypes.c_int * num_pids
        pids = pid_array_type()

        bytes_written = self._libproc.proc_listpids(
            PROC_ALL_PIDS, 0, ctypes.byref(pids), buf_size
        )
        if bytes_written <= 0:
            return self._collect_via_posix_ps()

        actual_count = bytes_written // ctypes.sizeof(ctypes.c_int)

        name_buf = ctypes.create_string_buffer(1024)
        path_buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)

        for i in range(actual_count):
            pid = pids[i]
            if pid <= 0:
                continue

            name = None
            path = None

            # Get executable path: proc_pidpath(int pid, void *buffer, uint32_t buffersize)
            try:
                ret_path = self._libproc.proc_pidpath(
                    pid, path_buf, PROC_PIDPATHINFO_MAXSIZE
                )
                if ret_path > 0:
                    path = path_buf.value.decode("utf-8", errors="replace")
                    name = os.path.basename(path)
            except Exception:
                pass

            # If name not yet known, try proc_name(int pid, void *buffer, uint32_t buffersize)
            if not name:
                try:
                    ret_name = self._libproc.proc_name(pid, name_buf, 1024)
                    if ret_name > 0:
                        name = name_buf.value.decode("utf-8", errors="replace")
                except Exception:
                    pass

            if not name:
                name = f"proc_{pid}"

            processes.append(
                ProcessInfo(
                    pid=pid,
                    name=name,
                    path=path,
                )
            )

        return processes

    def _collect_via_posix_ps(self) -> List[ProcessInfo]:
        """POSIX standard utility fallback available on macOS / Darwin systems."""
        import subprocess

        processes: List[ProcessInfo] = []
        try:
            output = subprocess.check_output(
                ["/bin/ps", "-ax", "-o", "pid,ppid,comm"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            )
            lines = output.strip().splitlines()
            if not lines:
                return processes

            # Skip header line (PID PPID COMM)
            for line in lines[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    try:
                        pid = int(parts[0])
                        ppid = int(parts[1])
                        raw_comm = parts[2]
                        name = os.path.basename(raw_comm)
                        processes.append(
                            ProcessInfo(
                                pid=pid,
                                name=name,
                                parent={"pid": ppid, "name": "unknown"},
                            )
                        )
                    except ValueError:
                        continue
        except Exception:
            pass
        return processes
