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
    "vmware, inc.",
    "python software foundation",
    "github, inc.",
    "docker inc",
    "discord inc.",
    "zoom video communications, inc.",
    "mozilla corporation",
]


class SignatureVerifier:
    """Verifies Authenticode signatures and classifies trusted publishers."""

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
        """Verify signatures for a batch of executable file paths."""
        results: Dict[str, Dict[str, Any]] = {}
        if sys.platform != "win32" or not file_paths:
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

        # 2. Query in chunks of 50 to avoid exceeding PowerShell command-line length
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
                # Fallback for errors in chunk
                for path in chunk:
                    if path not in results:
                        results[path] = {"status": "UNVERIFIED", "publisher": ""}

        # Ensure all requested paths have a result
        for p in file_paths:
            if p not in results:
                results[p] = {"status": "UNVERIFIED", "publisher": ""}

        return results
