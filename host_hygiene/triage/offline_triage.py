"""Offline Rule-Based Triage Engine: Enriched forensic triage when LLM API is unavailable."""

import re
from typing import List, Dict, Any, Optional

from ..collector.base import ProcessInfo
from ..detector.anomaly_engine import AnomalyFinding
from .base import BaseTriageEngine, ProcessTriageEvaluation, TriageReport

# Catalog of common benign third-party software categories
KNOWN_BENIGN_SOFTWARE: Dict[str, str] = {
    # Browsers
    "chrome": "Google Chrome web browser",
    "firefox": "Mozilla Firefox web browser",
    "msedge": "Microsoft Edge web browser",
    "brave": "Brave Privacy Browser",
    "opera": "Opera web browser",
    "safari": "Apple Safari web browser",
    "vivaldi": "Vivaldi web browser",
    # Development & Runtime
    "code": "Visual Studio Code editor",
    "pycharm": "JetBrains PyCharm IDE",
    "idea64": "JetBrains IntelliJ IDEA IDE",
    "python": "Python programming language interpreter",
    "python3": "Python 3 programming language interpreter",
    "py": "Python Windows Launcher",
    "node": "Node.js JavaScript runtime",
    "npm": "Node Package Manager CLI",
    "git": "Git version control system",
    "docker": "Docker container runtime engine",
    "dockerd": "Docker daemon service",
    "containerd": "Container runtime daemon",
    "podman": "Podman container management tool",
    "kubectl": "Kubernetes CLI controller",
    "cargo": "Rust Cargo package manager",
    "rustc": "Rust compiler",
    "go": "Go compiler and runtime",
    "java": "Java Virtual Machine runtime",
    "dotnet": ".NET Core host application",
    "vmware": "VMware Workstation virtualization host",
    "vmware-vmx": "VMware virtual machine engine worker",
    "mkssandbox": "VMware graphics rendering sandbox process",
    "git-bash": "Git for Windows Bash environment",
    "mintty": "MinTTY terminal emulator",
    # Productivity & Communication
    "slack": "Slack workplace messaging client",
    "teams": "Microsoft Teams collaboration app",
    "discord": "Discord voice and chat client",
    "zoom": "Zoom video conferencing client",
    "spotify": "Spotify digital music streaming client",
    "outlook": "Microsoft Outlook email client",
    "notion": "Notion workspace application",
    "obsidian": "Obsidian knowledge base app",
    # Terminals & Shells
    "powershell": "PowerShell interactive shell",
    "pwsh": "PowerShell Core cross-platform shell",
    "cmd": "Windows Command Prompt interpreter",
    "windowsterminal": "Windows Terminal host",
    "bash": "GNU Bourne-Again Shell",
    "zsh": "Z shell interpreter",
    "fish": "Fish friendly interactive shell",
    "tmux": "Terminal multiplexer",
    # Cloud & Virtualization
    "wsl": "Windows Subsystem for Linux host",
    "wslhost": "WSL host process",
    "vmtoolsd": "VMware Tools guest service daemon",
    "vboxservice": "VirtualBox Guest Additions service",
    "qemu-ga": "QEMU guest agent daemon",
    "google_guest_agent": "Google Cloud guest environment agent",
    "amazon-ssm-agent": "AWS Systems Manager agent",
}


class OfflineTriageEngine(BaseTriageEngine):
    """Rule-based offline triage engine with enriched telemetry evaluation."""

    def triage(
        self,
        candidate_processes: List[ProcessInfo],
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        total_inspected: int,
        noise_filtered_count: int,
        platform_name: str,
        persistence_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> TriageReport:
        evaluated: List[ProcessTriageEvaluation] = []
        host_recommendations: List[str] = []
        persistence_list = persistence_findings or []

        total_anomalies = 0
        critical_count = 0
        high_count = 0
        unclassified_count = 0

        for proc in candidate_processes:
            findings = anomalies_by_pid.get(proc.pid, [])
            total_anomalies += len(findings)

            clean = proc.clean_name
            purpose, risk, reasoning, recs = self._evaluate_single(proc, findings)

            if risk == "Malicious":
                critical_count += 1
            elif risk == "Suspicious":
                high_count += 1
            else:
                if clean not in KNOWN_BENIGN_SOFTWARE and not proc.classification:
                    unclassified_count += 1

            evaluated.append(
                ProcessTriageEvaluation(
                    pid=proc.pid,
                    process_name=proc.name,
                    purpose=purpose,
                    risk_rating=risk,
                    reasoning=reasoning,
                    actionable_recommendations=recs,
                    anomaly_findings=[f.to_dict() for f in findings],
                    path=proc.path,
                    parent=proc.parent,
                    command_line=proc.command_line,
                    sha256=proc.sha256,
                    user=proc.user,
                    signature=proc.signature,
                    network_connections=proc.network_connections,
                    classification=proc.classification,
                )
            )

        # Persistence risk evaluation
        suspicious_persist = [p for p in persistence_list if p.get("is_user_writable")]
        persist_penalty = min(25, len(suspicious_persist) * 8)

        # Calculate Hygiene Score (0 - 100)
        score_penalty = (
            (critical_count * 35)
            + (high_count * 20)
            + persist_penalty
            + (min(15, unclassified_count * 2))
        )
        hygiene_score = max(0, min(100, 100 - score_penalty))

        # Overall risk level
        if critical_count > 0:
            overall_risk = "Critical"
            summary = (
                f"Critical security alerts detected! Found {critical_count} malicious "
                f"or heavily compromised process(es) (e.g. masquerading paths, shell injection, or C2). Immediate remediation required."
            )
        elif high_count > 0 or len(suspicious_persist) > 0:
            overall_risk = "Suspicious"
            summary = (
                f"Suspicious host anomalies detected! Found {high_count} suspicious process(es) "
                f"and {len(suspicious_persist)} autostart persistence item(s) in user-writable paths."
            )
        elif hygiene_score < 85:
            overall_risk = "Elevated"
            summary = (
                f"Host is operating with several unclassified background applications. Baseline tuning recommended."
            )
        else:
            overall_risk = "Benign"
            summary = (
                f"Host hygiene is healthy. Active processes conform to legitimate OS, OEM, and developer baselines."
            )

        # Host-level recommendations
        if critical_count > 0:
            host_recommendations.append("Isolate this endpoint from the local network segment immediately.")
            host_recommendations.append("Collect volatile memory dumps before terminating suspicious processes.")
            host_recommendations.append("Review authentication logs, anomalous parent processes, and outbound sockets.")
        elif high_count > 0:
            host_recommendations.append("Investigate processes flagged for typosquatting, hidden flags, or anomalous lineage.")
            host_recommendations.append("Verify digital code signatures (Authenticode / Apple Codesign / Package verification) and originating disk paths.")
        else:
            host_recommendations.append("Maintain routine host hygiene checks.")
            if unclassified_count > 0:
                host_recommendations.append(
                    "Consider caching legitimate internal tools in 'baseline_cache.json'."
                )

        if suspicious_persist:
            host_recommendations.append(
                f"Audit {len(suspicious_persist)} autostart persistence item(s) pointing to user-writable directories."
            )

        return TriageReport(
            hygiene_score=hygiene_score,
            overall_risk=overall_risk,
            summary=summary,
            evaluated_processes=evaluated,
            host_recommendations=host_recommendations,
            mode="offline_fallback",
            model_used=None,
            total_inspected=total_inspected,
            noise_filtered_count=noise_filtered_count,
            candidate_count=len(candidate_processes),
            anomalies_detected_count=total_anomalies,
            persistence_findings=persistence_list,
        )

    def _evaluate_single(
        self, proc: ProcessInfo, findings: List[AnomalyFinding]
    ) -> tuple[str, str, str, List[str]]:
        """Evaluate a single candidate process using enriched deterministic rules."""
        clean = proc.clean_name
        recs: List[str] = []

        # 1. Critical Anomalies (IOC, Masquerading Path, Shell Lineage, Homoglyphs)
        critical_findings = [f for f in findings if f.severity == "CRITICAL"]
        if critical_findings:
            f = critical_findings[0]
            purpose = f"Hostile or masquerading artifact: {f.description}"
            risk = "Malicious"
            reasoning = (
                f"Process '{proc.name}' triggered critical security alert '{f.anomaly_type}'. "
                f"Details: {f.description}"
            )
            recs.append(f"Terminate PID {proc.pid} ({proc.name}) and audit parent process tree.")
            recs.append(f"Inspect disk binary at '{proc.path or 'executable location'}' for hash and digital signature.")
            recs.append("Check for active outbound network sockets using netstat / ss.")
            return purpose, risk, reasoning, recs

        # 2. High Severity Anomalies (Typosquatting, Double Extensions, Hidden Cmdline)
        high_findings = [f for f in findings if f.severity == "HIGH"]
        if high_findings:
            f = high_findings[0]
            purpose = f"Potential deceptive software or evasive tool: {f.description}"
            risk = "Suspicious"
            reasoning = (
                f"Process '{proc.name}' exhibits suspicious behavior: {f.anomaly_type}."
            )
            recs.append(f"Verify authenticity, binary path, and launch parameters of PID {proc.pid}.")
            recs.append(f"Confirm whether '{proc.name}' was intentionally deployed by system administrators.")
            return purpose, risk, reasoning, recs

        # 3. Medium Severity Anomalies (High entropy, cross-platform extensions)
        med_findings = [f for f in findings if f.severity == "MEDIUM"]
        if med_findings:
            f = med_findings[0]
            purpose = f"Uncommon executable pattern: {f.description}"
            risk = "Suspicious"
            reasoning = f"Triggered heuristic alert '{f.anomaly_type}': {f.description}"
            recs.append(f"Inspect binary path ('{proc.path or 'unknown'}') and launch parameters.")
            return purpose, risk, reasoning, recs

        # 4. Check Hardware & OEM Classifications
        if proc.classification:
            if proc.classification == "OEM:Lenovo":
                purpose = "Lenovo / ThinkPad OEM hardware management utility."
                risk = "Benign"
                reasoning = "Recognized ThinkPad platform utility with valid signature/baseline match."
                return purpose, risk, reasoning, recs
            elif proc.classification == "OEM:Intel":
                purpose = "Intel Core Ultra / Intel platform management service."
                risk = "Benign"
                reasoning = "Recognized Intel platform component with valid signature/baseline match."
                return purpose, risk, reasoning, recs
            elif proc.classification == "DevTools":
                purpose = "Developer tool / virtualization runtime component."
                risk = "Benign"
                reasoning = "Recognized developer environment utility (VMware, Git, Python, Docker)."
                return purpose, risk, reasoning, recs

        # 5. Check if signed by trusted vendor (Microsoft, Intel, Lenovo)
        sig = proc.signature or {}
        if sig.get("status") == "VALID":
            pub = sig.get("publisher", "")
            purpose = f"Verified commercial software signed by '{pub}'."
            risk = "Benign"
            reasoning = f"Authenticode signature is VALID ({pub}) with zero detected anomaly indicators."
            return purpose, risk, reasoning, recs

        # 6. Known Benign Third-Party Application
        if clean in KNOWN_BENIGN_SOFTWARE:
            desc = KNOWN_BENIGN_SOFTWARE[clean]
            purpose = desc
            risk = "Benign"
            reasoning = f"Recognized standard user application ({desc}) with zero anomaly indicators."
            return purpose, risk, reasoning, recs

        # 7. Check if it matches known naming conventions (e.g. *daemon, *agent, *service)
        if re.search(r"(agent|daemon|service|helper|update|host)$", clean):
            purpose = "Auxiliary background service, agent, or update worker."
            risk = "Benign"
            reasoning = "Standard auxiliary utility without suspicious naming or IOC triggers."
            return purpose, risk, reasoning, recs

        # 8. Unclassified / Unknown Third-Party Binary
        purpose = f"Unclassified third-party software / custom binary '{proc.name}'."
        risk = "Benign"
        reasoning = (
            f"Process '{proc.name}' is not part of the standard OS baseline or common catalog, "
            f"but does not display typosquatting, homoglyphs, or IOC characteristics."
        )
        recs.append(f"Confirm if '{proc.name}' is an authorized internal or developer tool.")
        return purpose, risk, reasoning, recs
