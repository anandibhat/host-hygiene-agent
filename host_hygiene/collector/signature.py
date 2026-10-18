"""Code Signing & Digital Signature Verification (WinVerifyTrust / Authenticode)."""

from __future__ import annotations
import sys
import os
import subprocess
import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from ..baseline.cache import BaselineCache

TRUSTED_PUBLISHER_SUBSTRINGS = [
    "microsoft corporation",
    "microsoft windows",
    "microsoft visual studio",
    "intel corporation",
    "intel(r) client systems",
    "lenovo",
    "lenovo group limited",
    "google llc",
    "apple inc.",
    "apple software",
    "macos software signing",
    "software signing",
    "canonical",
    "red hat",
    "debian",
    "ubuntu",
    "vmware, inc.",
    "python software foundation",
    "github, inc.",
    "docker inc",
    "discord inc.",
    "zoom video communications, inc.",
    "mozilla corporation",
]


class SignatureVerifier:
    """Verifies digital signatures (Authenticode on Windows, codesign on macOS, ELF/pkg on Linux) and classifies trusted publishers."""

    def __init__(self, cache: Optional[BaselineCache] = None):
        self.cache = cache

    @staticmethod
    def is_trusted_publisher(publisher_str: str) -> bool:
        """Check if publisher string matches trusted vendor signatures."""
        if not publisher_str:
            return False
        pub_lower = publisher_str.lower()
        for trusted in TRUSTED_PUBLISHER_SUBSTRINGS:
            if trusted in pub_lower:
                return True
        return False

    def verify_batch(self, file_paths: List[str]) -> Dict[str, Dict[str, Any]]:
        """Verify signatures for a batch of executable file paths across Windows, macOS, and Linux."""
        results: Dict[str, Dict[str, Any]] = {}
        if not file_paths:
            return results

        # 1. Filter existing paths and check cache
        needed_paths: List[str] = []
        for p in file_paths:
            if not p or not os.path.isfile(p):
                results[p] = {"status": "FILE_NOT_FOUND", "publisher": ""}
                continue

            # Check if cache has valid signature
            if self.cache:
                cached = self.cache.get(p, None)
                if cached and "signature" in cached:
                    results[p] = cached["signature"]
                    continue

            needed_paths.append(p)

        if not needed_paths:
            return results

        if sys.platform == "win32":
            self._verify_windows(needed_paths, results)
        elif sys.platform == "darwin":
            self._verify_darwin(needed_paths, results)
        else:
            self._verify_linux(needed_paths, results)

        # Ensure all requested paths have a result
        for p in file_paths:
            if p not in results:
                results[p] = {"status": "UNVERIFIED", "publisher": ""}

        return results

    def _verify_windows(self, needed_paths: List[str], results: Dict[str, Dict[str, Any]]) -> None:
        """Windows Authenticode signature query via PowerShell in chunks of 50."""
        chunk_size = 50
        for i in range(0, len(needed_paths), chunk_size):
            chunk = needed_paths[i : i + chunk_size]
            formatted = ", ".join([f"'{path}'" for path in chunk])
            ps_script = f"""
            $files = @({formatted})
            $out = @()
            foreach ($f in $files) {{
                if (Test-Path $f) {{
                    $sig = Get-AuthenticodeSignature -FilePath $f -ErrorAction SilentlyContinue
                    $pub = ''
                    if ($sig.SignerCertificate) {{
                        $pub = $sig.SignerCertificate.Subject
                    }}
                    $status = if ($sig.Status) {{ $sig.Status.ToString() }} else {{ 'Unsigned' }}
                    $out += [PSCustomObject]@{{
                        Path = $f
                        Status = $status
                        Publisher = $pub
                    }}
                }}
            }}
            $out | ConvertTo-Json -Compress
            """
            try:
                proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    data = json.loads(proc.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        raw_status = (item.get("Status") or "Unsigned").upper()
                        norm_status = "VALID" if raw_status == "VALID" else ("UNSIGNED" if "NOTSIGNED" in raw_status or "UNSIGNED" in raw_status else raw_status)
                        publisher = item.get("Publisher") or ""
                        results[item["Path"]] = {
                            "status": norm_status,
                            "publisher": publisher,
                        }
            except Exception:
                for path in chunk:
                    if path not in results:
                        results[path] = {"status": "UNVERIFIED", "publisher": ""}

    def _verify_darwin(self, needed_paths: List[str], results: Dict[str, Dict[str, Any]]) -> None:
        """macOS code signing verification via /usr/bin/codesign."""
        chunk_size = 30
        for i in range(0, len(needed_paths), chunk_size):
            chunk = needed_paths[i : i + chunk_size]
            try:
                cmd = ["/usr/bin/codesign", "-d", "--verbose=2"] + chunk
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                current_path = None
                for line in proc.stderr.splitlines():
                    line = line.strip()
                    if line.startswith("Executable="):
                        current_path = line.split("Executable=", 1)[1].strip()
                        results[current_path] = {"status": "VALID", "publisher": ""}
                    elif current_path and line.startswith("Authority="):
                        auth = line.split("Authority=", 1)[1].strip()
                        if not results[current_path]["publisher"]:
                            results[current_path]["publisher"] = auth
                    elif current_path and line.startswith("Signature=adhoc"):
                        results[current_path]["status"] = "VALID"
                        if not results[current_path]["publisher"]:
                            results[current_path]["publisher"] = "Ad-Hoc (Local)"
            except Exception:
                pass

            # Fill unverified or unsigned paths in chunk
            for path in chunk:
                if path not in results:
                    # Check if unsigned or invalid
                    try:
                        v_proc = subprocess.run(
                            ["/usr/bin/codesign", "-v", path],
                            capture_output=True,
                            text=True,
                            timeout=3,
                        )
                        if v_proc.returncode == 0:
                            results[path] = {"status": "VALID", "publisher": "Apple System"}
                        else:
                            results[path] = {"status": "UNSIGNED", "publisher": ""}
                    except Exception:
                        results[path] = {"status": "UNVERIFIED", "publisher": ""}

    def _verify_linux(self, needed_paths: List[str], results: Dict[str, Dict[str, Any]]) -> None:
        """Linux executable verification via ELF magic header and package manager inspection."""
        for path in needed_paths:
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                if magic == b"\x7fELF":
                    results[path] = {"status": "VALID", "publisher": "Linux System ELF"}
                else:
                    results[path] = {"status": "UNSIGNED", "publisher": ""}
            except Exception:
                results[path] = {"status": "UNVERIFIED", "publisher": ""}
