"""Anomaly Detection Engine: Typosquatting, Homoglyphs, IOCs, and Enriched Forensic Checks.

Evaluates canonical OS paths, parent-child lineage, command line arguments,
Authenticode signatures, privilege levels, and network connections.
"""

import math
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from ..collector.base import ProcessInfo
from ..baseline.signatures import (
    PROTECTED_CORE_NAMES,
    CANONICAL_OS_PATHS,
    MANDATORY_SYSTEM_PROCESSES,
)
from ..collector.network import SUSPICIOUS_PORTS
from .ioc_database import IOC_DATABASE
from .similarity import (
    normalize_homoglyphs,
    has_invisible_or_bidi_characters,
    has_unicode_homoglyphs,
    damerau_levenshtein_distance,
    calculate_similarity,
)

# High-risk parent processes that should NOT spawn interactive shells or scripting engines
EXPLOIT_PRONE_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "w3wp.exe",
    "httpd.exe",
    "nginx.exe",
    "tomcat.exe",
    "sqlservr.exe",
}

# Dangerous spawned child processes (shells, script hosts, LOLBins)
DANGEROUS_SPAWNED_CHILDREN = {
    "cmd.exe",
    "cmd",
    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",
    "bash.exe",
    "bash",
    "sh.exe",
    "sh",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "vssadmin.exe",
    "whoami.exe",
}


@dataclass
class AnomalyFinding:
    """Represents an anomaly detected in a process."""
    process_pid: int
    process_name: str
    anomaly_type: str  # TYPOSQUATTING, IOC_MATCH, CANONICAL_PATH_MISMATCH, etc.
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    target_os_component: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.process_pid,
            "process_name": self.process_name,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "target_os_component": self.target_os_component,
            "details": self.details,
        }


class AnomalyDetectionEngine:
    """Detects suspicious naming patterns, typosquatting, masquerading, and anomalous forensic telemetry."""

    def __init__(self, platform_name: str = "windows"):
        self.platform_name = platform_name.lower()
        self._init_protected_targets()

    def _init_protected_targets(self):
        """Prepare target names for typosquatting checks."""
        self.protected_names = set()
        plat_key = "windows" if "win" in self.platform_name else (
            "darwin" if ("darwin" in self.platform_name or "mac" in self.platform_name) else "linux"
        )
        for name in PROTECTED_CORE_NAMES.get(plat_key, []):
            clean = name.lower()
            if clean.endswith(".exe"):
                clean = clean[:-4]
            self.protected_names.add(clean)

        for key, names in PROTECTED_CORE_NAMES.items():
            for name in names:
                clean = name.lower()
                if clean.endswith(".exe"):
                    clean = clean[:-4]
                self.protected_names.add(clean)

    def analyze_process(self, process: ProcessInfo) -> List[AnomalyFinding]:
        """Analyze a single process for all anomaly categories including enriched telemetry."""
        findings: List[AnomalyFinding] = []

        raw_name = process.name
        clean_name = process.clean_name

        # 1. Check for invisible, zero-width, or bidi control characters
        has_bidi, bidi_chars = has_invisible_or_bidi_characters(raw_name)
        if has_bidi:
            findings.append(
                AnomalyFinding(
                    process_pid=process.pid,
                    process_name=raw_name,
                    anomaly_type="INVISIBLE_CONTROL_CHARS",
                    severity="CRITICAL",
                    description=f"Process name contains hidden or bidirectional override control characters: {', '.join(bidi_chars)}",
                    details={"control_chars": bidi_chars},
                )
            )

        # 2. Check for Unicode homoglyphs (e.g. Cyrillic letters mimicking Latin)
        has_uni, uni_chars = has_unicode_homoglyphs(raw_name)
        if has_uni:
            findings.append(
                AnomalyFinding(
                    process_pid=process.pid,
                    process_name=raw_name,
                    anomaly_type="UNICODE_HOMOGLYPH_INJECTION",
                    severity="CRITICAL",
                    description=f"Process name utilizes non-ASCII unicode homoglyphs: {', '.join(uni_chars)}",
                    details={"homoglyphs": uni_chars},
                )
            )

        # 3. Check for Known IOC Matches
        ioc_hit = self._check_ioc(clean_name, raw_name)
        if ioc_hit:
            findings.append(
                AnomalyFinding(
                    process_pid=process.pid,
                    process_name=raw_name,
                    anomaly_type="IOC_MATCH",
                    severity=ioc_hit["severity"],
                    description=f"Matches known IOC/attack tool ({ioc_hit['category']}): {ioc_hit['description']}",
                    details=ioc_hit,
                )
            )

        # 4. Check for Typosquatting and Homoglyph Masquerading against protected OS components
        typo_findings = self._check_typosquatting(raw_name, clean_name, process.pid)
        findings.extend(typo_findings)

        # 5. Check Canonical OS Path Validation (e.g. svchost.exe outside System32)
        path_finding = self._check_canonical_path(clean_name, raw_name, process.path, process.pid)
        if path_finding:
            findings.append(path_finding)

        # 6. Check Parent Process Lineage (e.g. Office apps/browsers spawning cmd/powershell)
        lineage_finding = self._check_parent_lineage(clean_name, raw_name, process.parent, process.pid)
        if lineage_finding:
            findings.append(lineage_finding)

        # 7. Check Command-Line Arguments (-enc, -w hidden, IEX, download cradle)
        cmd_findings = self._check_command_line(raw_name, process.command_line, process.pid)
        findings.extend(cmd_findings)

        # 8. Check Privilege Level / User Account Mismatches
        priv_finding = self._check_privilege_mismatch(clean_name, raw_name, process.user, process.pid)
        if priv_finding:
            findings.append(priv_finding)

        # 9. Check Code Signing / Authenticode Status
        sig_finding = self._check_signature(clean_name, raw_name, process.signature, process.pid)
        if sig_finding:
            findings.append(sig_finding)

        # 10. Check Active Network Connections
        net_findings = self._check_network(clean_name, raw_name, process.network_connections, process.pid)
        findings.extend(net_findings)

        # 11. Check for Double Extensions (e.g., report.pdf.exe)
        double_ext_finding = self._check_double_extension(raw_name, process.pid)
        if double_ext_finding:
            findings.append(double_ext_finding)

        # 12. Check for Trailing Whitespace or Dots (e.g., "svchost.exe ")
        trailing_finding = self._check_trailing_characters(raw_name, process.pid)
        if trailing_finding:
            findings.append(trailing_finding)

        # 13. Check for Non-native Executable Extension on Linux / macOS
        plat = self.platform_name
        if "win" not in plat:
            if raw_name.lower().endswith((".exe", ".scr", ".bat", ".pif", ".cmd", ".vbs")):
                findings.append(
                    AnomalyFinding(
                        process_pid=process.pid,
                        process_name=raw_name,
                        anomaly_type="SUSPICIOUS_EXTENSION",
                        severity="MEDIUM",
                        description=f"Windows executable extension '{raw_name}' executing natively on non-Windows host ({plat}).",
                        details={"platform": plat},
                    )
                )

        # 14. High entropy / generated random process name
        entropy_finding = self._check_entropy_and_randomness(clean_name, raw_name, process.pid)
        if entropy_finding:
            findings.append(entropy_finding)

        return findings

    def _check_canonical_path(
        self, clean_name: str, raw_name: str, path: Optional[str], pid: int
    ) -> Optional[AnomalyFinding]:
        """Validate executable path against canonical operating system directory."""
        if not path or "win" not in self.platform_name:
            return None

        # Check with .exe extension
        exe_name = f"{clean_name}.exe"
        if exe_name in CANONICAL_OS_PATHS:
            allowed_paths = [p.lower() for p in CANONICAL_OS_PATHS[exe_name]]
            norm_path = path.lower()

            # Check if current path matches any allowed canonical paths
            matches = any(
                norm_path == ap or norm_path.startswith(os.path.dirname(ap))
                for ap in allowed_paths
            )
            if not matches:
                return AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="CANONICAL_PATH_MISMATCH",
                    severity="CRITICAL",
                    description=(
                        f"Core system process '{exe_name}' running from non-canonical location "
                        f"'{path}' (expected '{allowed_paths[0]}'). Masquerading payload alert!"
                    ),
                    target_os_component=exe_name,
                    details={"actual_path": path, "expected_path": allowed_paths[0]},
                )
        return None

    def _check_parent_lineage(
        self, clean_name: str, raw_name: str, parent: Optional[Dict[str, Any]], pid: int
    ) -> Optional[AnomalyFinding]:
        """Detect anomalous parent-child lineage (e.g. Office or browser spawning shell)."""
        if not parent or not parent.get("name"):
            return None

        p_name = parent["name"].lower().strip()
        p_pid = parent.get("pid", 0)

        # Normalize parent executable name
        if p_name.endswith(".exe"):
            p_clean = p_name[:-4]
        else:
            p_clean = p_name

        child_norm = f"{clean_name}.exe" if not clean_name.endswith(".exe") else clean_name
        parent_norm = f"{p_clean}.exe" if not p_clean.endswith(".exe") else p_clean

        if parent_norm in EXPLOIT_PRONE_PARENTS:
            if child_norm in DANGEROUS_SPAWNED_CHILDREN or clean_name in DANGEROUS_SPAWNED_CHILDREN:
                return AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="ANOMALOUS_PARENT_LINEAGE",
                    severity="CRITICAL",
                    description=(
                        f"Anomalous execution lineage: '{parent_norm}' (PID {p_pid}) "
                        f"spawned shell/interpreter '{raw_name}'. Indicator of weaponized exploit payload!"
                    ),
                    details={"parent_name": parent_norm, "parent_pid": p_pid, "child_name": raw_name},
                )
        return None

    def _check_command_line(
        self, raw_name: str, command_line: Optional[str], pid: int
    ) -> List[AnomalyFinding]:
        """Inspect launch arguments for hidden windows, encoded payloads, or LOLBin abuse."""
        findings: List[AnomalyFinding] = []
        if not command_line:
            return findings

        cmd_lower = command_line.lower()

        # 1. Encoded PowerShell command (-enc, -encodedcommand)
        if re.search(r"\s+-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}", cmd_lower):
            findings.append(
                AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="ENCODED_COMMAND_EXECUTION",
                    severity="CRITICAL",
                    description="Execution utilizes base64-encoded command string (-enc/-EncodedCommand), common in obfuscated C2/droppers.",
                    details={"command_line": command_line[:200]},
                )
            )

        # 2. Hidden Window Style (-w hidden, -windowstyle hidden)
        if re.search(r"\s+-(?:w|windowstyle)\s+(?:hidden|1)", cmd_lower):
            findings.append(
                AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="HIDDEN_WINDOW_EXECUTION",
                    severity="HIGH",
                    description="Process launched with hidden window style (-w hidden) to evade user observation.",
                    details={"command_line": command_line[:200]},
                )
            )

        # 3. ExecutionPolicy Bypass (-ep bypass, -executionpolicy bypass)
        if re.search(r"\s+-(?:ep|executionpolicy)\s+bypass", cmd_lower):
            findings.append(
                AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="EXECUTION_POLICY_BYPASS",
                    severity="MEDIUM",
                    description="PowerShell launched with '-ExecutionPolicy Bypass' argument.",
                    details={"command_line": command_line[:200]},
                )
            )

        # 4. In-Memory Download Cradle (DownloadString / IEX)
        if (
            ("downloadstring" in cmd_lower or "downloaddata" in cmd_lower or "iwr" in cmd_lower)
            and ("iex" in cmd_lower or "invoke-expression" in cmd_lower)
        ):
            findings.append(
                AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="MEMORY_DOWNLOAD_CRADLE",
                    severity="CRITICAL",
                    description="Command line contains in-memory script download and execution cradle (DownloadString | IEX).",
                    details={"command_line": command_line[:200]},
                )
            )

        # 5. Shadow Copy Deletion (Ransomware Tactic)
        if "vssadmin" in cmd_lower and "delete" in cmd_lower and "shadows" in cmd_lower:
            findings.append(
                AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="SHADOW_COPY_DELETION",
                    severity="CRITICAL",
                    description="Command line invokes vssadmin to delete Volume Shadow Copies, indicative of active ransomware.",
                    details={"command_line": command_line[:200]},
                )
            )

        return findings

    def _check_privilege_mismatch(
        self, clean_name: str, raw_name: str, user: Optional[str], pid: int
    ) -> Optional[AnomalyFinding]:
        """Detect core system processes running as standard users, or user apps elevated as SYSTEM."""
        if not user or "win" not in self.platform_name:
            return None

        exe_name = f"{clean_name}.exe"
        user_lower = user.lower()

        # Check if a mandatory system process is running as a non-SYSTEM user
        if exe_name in MANDATORY_SYSTEM_PROCESSES:
            if "system" not in user_lower and "local service" not in user_lower and "network service" not in user_lower:
                return AnomalyFinding(
                    process_pid=pid,
                    process_name=raw_name,
                    anomaly_type="PRIVILEGE_MISMATCH",
                    severity="CRITICAL",
                    description=(
                        f"Privilege Mismatch: Mandatory OS process '{exe_name}' running under user account "
                        f"'{user}' instead of NT AUTHORITY\\SYSTEM. Indicator of process impersonation or user-dropped fake binary!"
                    ),
                    target_os_component=exe_name,
                    details={"user": user, "expected": "NT AUTHORITY\\SYSTEM"},
                )
        return None

    def _check_signature(
        self, clean_name: str, raw_name: str, signature: Dict[str, Any], pid: int
    ) -> Optional[AnomalyFinding]:
        """Detect invalid, revoked, or untrusted digital signatures."""
        if not signature:
            return None

        status = signature.get("status", "").upper()
        if status == "INVALID":
            return AnomalyFinding(
                process_pid=pid,
                process_name=raw_name,
                anomaly_type="INVALID_DIGITAL_SIGNATURE",
                severity="CRITICAL",
                description=f"Authenticode signature validation failed for '{raw_name}'. Executable may be tampered with or revoked.",
                details=signature,
            )
        return None

    def _check_network(
        self, clean_name: str, raw_name: str, network_connections: List[Dict[str, Any]], pid: int
    ) -> List[AnomalyFinding]:
        """Correlate processes with suspicious ports or listeners."""
        findings: List[AnomalyFinding] = []
        if not network_connections:
            return findings

        for conn in network_connections:
            l_port = conn.get("local_port", 0)
            r_port = conn.get("remote_port", 0)
            conn_type = conn.get("type", "")

            # Check for known offensive/C2 listening ports
            if conn_type == "LISTEN" and l_port in SUSPICIOUS_PORTS:
                findings.append(
                    AnomalyFinding(
                        process_pid=pid,
                        process_name=raw_name,
                        anomaly_type="SUSPICIOUS_LISTENING_PORT",
                        severity="CRITICAL",
                        description=f"Process listening on known offensive/backdoor port {l_port} ({SUSPICIOUS_PORTS[l_port]}).",
                        details={"port": l_port, "protocol": conn.get("proto")},
                    )
                )

            # Check for suspicious remote connection destinations
            if conn_type == "ESTABLISHED" and r_port in SUSPICIOUS_PORTS:
                findings.append(
                    AnomalyFinding(
                        process_pid=pid,
                        process_name=raw_name,
                        anomaly_type="SUSPICIOUS_REMOTE_C2_PORT",
                        severity="CRITICAL",
                        description=f"Process established outbound connection to known C2 port {r_port} ({SUSPICIOUS_PORTS[r_port]}).",
                        details={"remote_address": conn.get("remote_address"), "remote_port": r_port},
                    )
                )

        return findings

    def _check_ioc(self, clean_name: str, raw_name: str) -> Optional[Dict[str, Any]]:
        """Check against the known threat indicator database."""
        if clean_name in IOC_DATABASE:
            return IOC_DATABASE[clean_name]
        raw_lower = raw_name.lower()
        if raw_lower in IOC_DATABASE:
            return IOC_DATABASE[raw_lower]

        for ioc_key, meta in IOC_DATABASE.items():
            if len(ioc_key) >= 4 and (
                clean_name.startswith(ioc_key)
                or raw_lower.startswith(ioc_key)
            ):
                return meta
        return None

    def _check_typosquatting(
        self, raw_name: str, clean_name: str, pid: int
    ) -> List[AnomalyFinding]:
        """Detect typosquatting, character substitutions (svch0st), and distance anomalies."""
        findings: List[AnomalyFinding] = []
        normalized_name = normalize_homoglyphs(clean_name)

        for protected in self.protected_names:
            if clean_name == protected:
                continue

            # Case A: Homoglyph substitution (e.g., 'svch0st' normalized becomes 'svchost')
            if normalized_name == protected and clean_name != protected:
                findings.append(
                    AnomalyFinding(
                        process_pid=pid,
                        process_name=raw_name,
                        anomaly_type="HOMOGLYPH_TYPOSQUATTING",
                        severity="CRITICAL",
                        description=f"High-confidence homoglyph typosquatting mimicking core system component '{protected}' (e.g. 0->o, 1->l).",
                        target_os_component=protected,
                        details={"normalized_to": protected, "original": clean_name},
                    )
                )
                continue

            # Case B: Masquerading suffix/prefix (e.g., 'svchost32', 'svchost_updater', 'services64')
            if len(protected) >= 6 and (
                clean_name.startswith(f"{protected}_")
                or clean_name.startswith(f"{protected}32")
                or clean_name.startswith(f"{protected}64")
                or clean_name.startswith(f"{protected}svc")
            ):
                findings.append(
                    AnomalyFinding(
                        process_pid=pid,
                        process_name=raw_name,
                        anomaly_type="MASQUERADING_SUFFIX",
                        severity="HIGH",
                        description=f"Process name '{raw_name}' appends deceptive suffix to protected system process '{protected}'.",
                        target_os_component=protected,
                        details={"base_component": protected},
                    )
                )
                continue

            # Case C: Damerau-Levenshtein distance (e.g., 'svchostt', 'scvhost', 'lsasss', 'systemdd')
            dist = damerau_levenshtein_distance(clean_name, protected)
            similarity = calculate_similarity(clean_name, protected)

            if len(protected) >= 4:
                if (dist == 1 and similarity >= 0.80) or (dist == 2 and len(protected) >= 6 and similarity >= 0.75):
                    findings.append(
                        AnomalyFinding(
                            process_pid=pid,
                            process_name=raw_name,
                            anomaly_type="TYPOSQUATTING",
                            severity="HIGH",
                            description=f"Process name '{raw_name}' is suspiciously similar to protected system process '{protected}' (edit distance: {dist}, similarity: {similarity:.2f}).",
                            target_os_component=protected,
                            details={"edit_distance": dist, "similarity": round(similarity, 3)},
                        )
                    )
                    continue

        return findings

    def _check_double_extension(self, raw_name: str, pid: int) -> Optional[AnomalyFinding]:
        """Check for disguised double extensions like .pdf.exe or .docx.exe."""
        pattern = re.compile(
            r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|mp3|mp4|zip|rar)\.(exe|scr|bat|cmd|vbs|pif|ps1)$",
            re.IGNORECASE,
        )
        match = pattern.search(raw_name)
        if match:
            return AnomalyFinding(
                process_pid=pid,
                process_name=raw_name,
                anomaly_type="DOUBLE_EXTENSION",
                severity="HIGH",
                description=f"Process uses deceptive double extension disguised as document/media: '{match.group(0)}'",
                details={"disguised_type": match.group(1), "executable_type": match.group(2)},
            )
        return None

    def _check_trailing_characters(self, raw_name: str, pid: int) -> Optional[AnomalyFinding]:
        """Check for trailing whitespace or periods used to evade simple path filters."""
        if raw_name.endswith(" ") or raw_name.endswith("."):
            return AnomalyFinding(
                process_pid=pid,
                process_name=raw_name,
                anomaly_type="TRAILING_DELIMITER_EVASION",
                severity="HIGH",
                description="Process name contains trailing space or period, commonly used for filter evasion.",
                details={"raw_name": repr(raw_name)},
            )
        return None

    def _check_entropy_and_randomness(
        self, clean_name: str, raw_name: str, pid: int
    ) -> Optional[AnomalyFinding]:
        """Calculate Shannon entropy to flag auto-generated random executable names."""
        if len(clean_name) < 12:
            return None

        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", clean_name):
            return None

        prob = [float(clean_name.count(c)) / len(clean_name) for c in set(clean_name)]
        entropy = -sum(p * math.log(p, 2) for p in prob)

        is_hex = bool(re.match(r"^[0-9a-fA-F]{16,}$", clean_name))
        if is_hex or (entropy > 3.9 and len(clean_name) >= 14):
            return AnomalyFinding(
                process_pid=pid,
                process_name=raw_name,
                anomaly_type="HIGH_ENTROPY_NAME",
                severity="MEDIUM",
                description=f"Process name appears randomly generated or high-entropy (entropy: {entropy:.2f}).",
                details={"entropy": round(entropy, 2), "is_hex": is_hex},
            )
        return None

    def analyze_processes(self, processes: List[ProcessInfo]) -> Dict[int, List[AnomalyFinding]]:
        """Analyze a list of candidate processes. Returns mapping of PID to findings."""
        results: Dict[int, List[AnomalyFinding]] = {}
        for proc in processes:
            findings = self.analyze_process(proc)
            if findings:
                results[proc.pid] = findings
        return results
