"""Persistence Auditing: Inspects Run/RunOnce registry keys, Startup folders, and Scheduled Tasks."""

import sys
import os
import csv
import io
import subprocess
from typing import List, Dict, Any

USER_WRITABLE_PATH_INDICATORS = [
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\downloads\\",
]


class PersistenceAuditor:
    """Audits common Windows autostart persistence mechanisms."""

    @staticmethod
    def audit() -> List[Dict[str, Any]]:
        """Audit registry Run keys, startup folders, and scheduled tasks."""
        findings: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            return findings

        findings.extend(PersistenceAuditor._audit_registry())
        findings.extend(PersistenceAuditor._audit_startup_folders())
        findings.extend(PersistenceAuditor._audit_scheduled_tasks())
        return findings

    @staticmethod
    def _audit_registry() -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        try:
            import winreg

            locations = [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM:RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:RunOnce"),
            ]
            for root, subkey, label in locations:
                try:
                    with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                        num_values = winreg.QueryInfoKey(key)[1]
                        for i in range(num_values):
                            name, val, _ = winreg.EnumValue(key, i)
                            str_val = str(val).strip()
                            is_suspicious = any(
                                p in str_val.lower() for p in USER_WRITABLE_PATH_INDICATORS
                            ) or str_val.lower().endswith((".vbs", ".ps1", ".bat", ".scr"))

                            entries.append({
                                "mechanism": "Registry Autostart",
                                "location": label,
                                "name": name,
                                "target": str_val,
                                "is_user_writable": is_suspicious,
                            })
                except OSError:
                    pass
        except Exception:
            pass
        return entries

    @staticmethod
    def _audit_startup_folders() -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        folders = [
            (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "User Startup Folder"),
            (os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "All Users Startup Folder"),
        ]
        for f, label in folders:
            if os.path.isdir(f):
                try:
                    for item in os.listdir(f):
                        if item.lower() != "desktop.ini":
                            full_path = os.path.join(f, item)
                            entries.append({
                                "mechanism": "Startup Folder",
                                "location": label,
                                "name": item,
                                "target": full_path,
                                "is_user_writable": True,
                            })
                except Exception:
                    pass
        return entries

    @staticmethod
    def _audit_scheduled_tasks() -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        try:
            p = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if p.returncode == 0:
                reader = csv.DictReader(io.StringIO(p.stdout))
                for row in reader:
                    action = (row.get("Task To Run") or "").strip()
                    task_name = (row.get("TaskName") or "").strip()
                    lower_act = action.lower()

                    # Ignore our own daily audit task and known benign updaters
                    if "hosthygienedailyaudit" in lower_act or not action:
                        continue

                    # Check if pointing to AppData, Temp, etc.
                    if any(p in lower_act for p in USER_WRITABLE_PATH_INDICATORS):
                        entries.append({
                            "mechanism": "Scheduled Task (User-Writable Target)",
                            "location": task_name,
                            "name": os.path.basename(task_name),
                            "target": action,
                            "is_user_writable": True,
                            "author": row.get("Author", ""),
                        })
        except Exception:
            pass
        return entries
