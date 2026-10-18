"""Persistence Auditing: Inspects Run/RunOnce registry keys, Startup folders, and Scheduled Tasks."""

import sys
import os
import csv
import io
import subprocess
from typing import List, Dict, Any

USER_WRITABLE_PATH_INDICATORS = [
    # Windows indicators
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\downloads\\",
    # macOS & Linux indicators
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/.trash/",
    "/downloads/",
]


class PersistenceAuditor:
    """Audits common autostart persistence mechanisms across Windows, macOS, and Linux."""

    @staticmethod
    def audit() -> List[Dict[str, Any]]:
        """Audit autostart mechanisms (registry/tasks on Windows, launchd on macOS, systemd/cron on Linux)."""
        findings: List[Dict[str, Any]] = []
        if sys.platform == "win32":
            findings.extend(PersistenceAuditor._audit_registry())
            findings.extend(PersistenceAuditor._audit_startup_folders())
            findings.extend(PersistenceAuditor._audit_scheduled_tasks())
        elif sys.platform == "darwin":
            findings.extend(PersistenceAuditor._audit_darwin_launchd())
            findings.extend(PersistenceAuditor._audit_darwin_cron())
        elif sys.platform.startswith("linux"):
            findings.extend(PersistenceAuditor._audit_linux_systemd())
            findings.extend(PersistenceAuditor._audit_linux_cron())
            findings.extend(PersistenceAuditor._audit_linux_autostart())
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

    @staticmethod
    def _audit_darwin_launchd() -> List[Dict[str, Any]]:
        """Audit macOS LaunchAgents and LaunchDaemons."""
        import plistlib

        entries: List[Dict[str, Any]] = []
        folders = [
            (os.path.expanduser("~/Library/LaunchAgents"), "User LaunchAgent"),
            ("/Library/LaunchAgents", "Global LaunchAgent"),
            ("/Library/LaunchDaemons", "System LaunchDaemon"),
        ]

        for folder, label in folders:
            if not os.path.isdir(folder):
                continue
            try:
                for item in os.listdir(folder):
                    if not item.endswith(".plist"):
                        continue
                    full_path = os.path.join(folder, item)
                    try:
                        with open(full_path, "rb") as fp:
                            pl = plistlib.load(fp)
                        prog = pl.get("Program")
                        if not prog and pl.get("ProgramArguments"):
                            args = pl.get("ProgramArguments")
                            prog = args[0] if isinstance(args, list) and args else str(args)
                        target_str = str(prog or "").strip()
                        lower_target = target_str.lower()
                        is_suspicious = any(
                            p in lower_target for p in USER_WRITABLE_PATH_INDICATORS
                        ) or lower_target.endswith((".sh", ".py", ".rb", ".pl"))

                        entries.append({
                            "mechanism": label,
                            "location": full_path,
                            "name": pl.get("Label") or item,
                            "target": target_str,
                            "is_user_writable": is_suspicious,
                        })
                    except Exception:
                        pass
            except Exception:
                pass
        return entries

    @staticmethod
    def _audit_darwin_cron() -> List[Dict[str, Any]]:
        """Audit user crontabs on macOS."""
        entries: List[Dict[str, Any]] = []
        try:
            proc = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        is_suspicious = any(
                            p in line.lower() for p in USER_WRITABLE_PATH_INDICATORS
                        )
                        entries.append({
                            "mechanism": "macOS User Crontab",
                            "location": "crontab",
                            "name": "CronJob",
                            "target": line,
                            "is_user_writable": is_suspicious,
                        })
        except Exception:
            pass
        return entries

    @staticmethod
    def _audit_linux_systemd() -> List[Dict[str, Any]]:
        """Audit Linux systemd user and system services."""
        entries: List[Dict[str, Any]] = []
        dirs = [
            (os.path.expanduser("~/.config/systemd/user"), "User Systemd Service"),
            ("/etc/systemd/system", "System Systemd Service"),
        ]
        for folder, label in dirs:
            if not os.path.isdir(folder):
                continue
            try:
                for item in os.listdir(folder):
                    if item.endswith(".service"):
                        full_path = os.path.join(folder, item)
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                                content = f.read()
                            is_suspicious = any(
                                p in content.lower() for p in USER_WRITABLE_PATH_INDICATORS
                            )
                            entries.append({
                                "mechanism": label,
                                "location": full_path,
                                "name": item,
                                "target": full_path,
                                "is_user_writable": is_suspicious,
                            })
                        except Exception:
                            pass
            except Exception:
                pass
        return entries

    @staticmethod
    def _audit_linux_cron() -> List[Dict[str, Any]]:
        """Audit Linux user crontabs."""
        entries: List[Dict[str, Any]] = []
        try:
            proc = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        is_suspicious = any(
                            p in line.lower() for p in USER_WRITABLE_PATH_INDICATORS
                        )
                        entries.append({
                            "mechanism": "Linux Crontab",
                            "location": "crontab",
                            "name": "CronJob",
                            "target": line,
                            "is_user_writable": is_suspicious,
                        })
        except Exception:
            pass
        return entries

    @staticmethod
    def _audit_linux_autostart() -> List[Dict[str, Any]]:
        """Audit Linux XDG autostart desktop entries."""
        entries: List[Dict[str, Any]] = []
        dirs = [
            (os.path.expanduser("~/.config/autostart"), "User XDG Autostart"),
            ("/etc/xdg/autostart", "System XDG Autostart"),
        ]
        for folder, label in dirs:
            if not os.path.isdir(folder):
                continue
            try:
                for item in os.listdir(folder):
                    if item.endswith(".desktop"):
                        full_path = os.path.join(folder, item)
                        entries.append({
                            "mechanism": label,
                            "location": full_path,
                            "name": item,
                            "target": full_path,
                            "is_user_writable": True if "user" in label.lower() else False,
                        })
            except Exception:
                pass
        return entries
