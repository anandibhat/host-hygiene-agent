"""AI Triage Engine: Leverages LLM to analyze unclassified processes, assess risk, and score hygiene."""

import json
import os
import re
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

from ..collector.base import ProcessInfo
from ..detector.anomaly_engine import AnomalyFinding
from .base import BaseTriageEngine, ProcessTriageEvaluation, TriageReport
from .offline_triage import OfflineTriageEngine

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class AITriageEngine(BaseTriageEngine):
    """Sends unclassified host processes and forensic telemetry to an LLM for expert triage."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_GEMINI_MODEL,
        offline_fallback: bool = True,
        timeout: int = 30,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.model = model
        self.offline_fallback = offline_fallback
        self.timeout = timeout
        self._fallback_engine = OfflineTriageEngine()

    def has_api_key(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def triage(
        self,
        candidate_processes: List[ProcessInfo],
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        total_inspected: int,
        noise_filtered_count: int,
        platform_name: str,
        persistence_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> TriageReport:
        """Execute AI triage on candidate processes, falling back to offline engine if unconfigured."""
        if not self.has_api_key():
            if self.offline_fallback:
                return self._fallback_engine.triage(
                    candidate_processes,
                    anomalies_by_pid,
                    total_inspected,
                    noise_filtered_count,
                    platform_name,
                    persistence_findings,
                )
            raise ValueError("No Gemini API key configured and offline fallback is disabled.")

        # If there are no candidate processes, return clean report
        if not candidate_processes:
            return TriageReport(
                hygiene_score=100,
                overall_risk="Benign",
                summary="All running processes match known standard OS baselines. Host is in pristine condition.",
                evaluated_processes=[],
                host_recommendations=["Maintain regular hygiene audits."],
                mode="ai",
                model_used=self.model,
                total_inspected=total_inspected,
                noise_filtered_count=noise_filtered_count,
                candidate_count=0,
                anomalies_detected_count=0,
                persistence_findings=persistence_findings or [],
            )

        # Build structured prompt for LLM
        prompt = self._build_prompt(
            candidate_processes,
            anomalies_by_pid,
            total_inspected,
            noise_filtered_count,
            platform_name,
            persistence_findings,
        )

        try:
            raw_response = self._call_gemini_api(prompt)
            parsed_data = self._parse_json_response(raw_response)
            return self._build_report_from_ai(
                parsed_data,
                candidate_processes,
                anomalies_by_pid,
                total_inspected,
                noise_filtered_count,
                persistence_findings or [],
            )
        except Exception as e:
            if self.offline_fallback:
                report = self._fallback_engine.triage(
                    candidate_processes,
                    anomalies_by_pid,
                    total_inspected,
                    noise_filtered_count,
                    platform_name,
                    persistence_findings,
                )
                report.summary = f"[AI Call Failed: {e}] (Fell back to Offline Mode) - {report.summary}"
                return report
            raise

    def _build_prompt(
        self,
        candidate_processes: List[ProcessInfo],
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        total_inspected: int,
        noise_filtered_count: int,
        platform_name: str,
        persistence_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Construct the prompt sent to the LLM with enriched telemetry."""
        proc_entries = []
        for p in candidate_processes:
            findings = [f.to_dict() for f in anomalies_by_pid.get(p.pid, [])]
            proc_entries.append({
                "pid": p.pid,
                "name": p.name,
                "path": p.path,
                "parent": p.parent,
                "command_line": p.command_line,
                "user": p.user,
                "sha256": p.sha256,
                "signature": p.signature,
                "network_connections": p.network_connections,
                "classification": p.classification,
                "anomaly_flags": findings,
            })

        proc_json = json.dumps(proc_entries, indent=2)
        persist_json = json.dumps(persistence_findings or [], indent=2)

        return f"""You are an elite Cybersecurity Incident Responder and Host Hygiene Triage Agent.
A forensic host security agent has inspected active processes on a {platform_name.upper()} endpoint.
Standard OS background noise ({noise_filtered_count} components out of {total_inspected} total) was filtered out using an OS baseline filter.

Below are the remaining {len(candidate_processes)} candidate/unclassified processes with enriched forensic telemetry (path, parent lineage, command line, user, sha256, digital signature, network connections, and anomaly flags):
```json
{proc_json}
```

Host Autostart Persistence Telemetry:
```json
{persist_json}
```

EVALUATION INSTRUCTIONS:
For each process in the list, evaluate:
1. Process purpose: What does this software normally do?
2. Risk rating: Must be exactly one of: "Benign", "Suspicious", or "Malicious".
   - Malicious: Known malware, C2 beacons, offensive tools, masquerading outside canonical paths (e.g. svchost outside System32), anomalous shell spawn lineage, or memory download cradles.
   - Suspicious: Living-off-the-land tools, unauthorized tunnels, deceptive extensions, or unverified background daemons.
   - Benign: Normal user applications, OEM hardware services (Lenovo, Intel), developer tools.
3. Actionable recommendations: Clear, prioritized steps for security engineers.
4. Calculate a Daily Hygiene Score for the host between 0 and 100.

OUTPUT FORMAT REQUIREMENTS:
You MUST respond with ONLY a valid, raw JSON object matching this schema:
{{
  "daily_hygiene_score": <int between 0 and 100>,
  "overall_risk": "<Benign | Suspicious | Elevated | Critical>",
  "summary": "<Executive summary of endpoint hygiene>",
  "host_recommendations": [
    "<High-level host remediation recommendation 1>",
    "<Recommendation 2>"
  ],
  "processes": [
    {{
      "pid": <int>,
      "process_name": "<str>",
      "purpose": "<What does this software normally do?>",
      "risk_rating": "<Benign | Suspicious | Malicious>",
      "reasoning": "<Technical reasoning>",
      "actionable_recommendations": [
        "<Actionable recommendation>"
      ]
    }}
  ]
}}
"""

    def _call_gemini_api(self, prompt: str) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp_text = resp.read().decode("utf-8")
            resp_json = json.loads(resp_text)
            candidates = resp_json.get("candidates", [])
            if not candidates:
                raise ValueError(f"No candidates returned by Gemini API: {resp_text}")
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise ValueError("No text content returned in Gemini candidate response")
            return parts[0].get("text", "")

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", cleaned)
            cleaned = re.sub(r"\n```$", "", cleaned)
            cleaned = cleaned.strip()

        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            cleaned = cleaned[first_brace : last_brace + 1]

        return json.loads(cleaned)

    def _build_report_from_ai(
        self,
        data: Dict[str, Any],
        candidate_processes: List[ProcessInfo],
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        total_inspected: int,
        noise_filtered_count: int,
        persistence_findings: List[Dict[str, Any]],
    ) -> TriageReport:
        score = int(data.get("daily_hygiene_score", 100))
        score = max(0, min(100, score))
        overall_risk = str(data.get("overall_risk", "Benign"))
        summary = str(data.get("summary", "AI Triage Completed."))
        host_recs = data.get("host_recommendations", [])
        if not isinstance(host_recs, list):
            host_recs = [str(host_recs)]

        eval_map = {}
        for p_data in data.get("processes", []):
            try:
                pid = int(p_data.get("pid", 0))
                eval_map[pid] = p_data
            except (ValueError, TypeError):
                continue

        evaluated_procs: List[ProcessTriageEvaluation] = []
        total_anomalies = 0

        for proc in candidate_processes:
            findings = anomalies_by_pid.get(proc.pid, [])
            total_anomalies += len(findings)

            ai_eval = eval_map.get(proc.pid)
            if ai_eval:
                purpose = ai_eval.get("purpose", "Unspecified purpose.")
                risk = ai_eval.get("risk_rating", "Benign")
                reasoning = ai_eval.get("reasoning", "")
                recs = ai_eval.get("actionable_recommendations", [])
                if not isinstance(recs, list):
                    recs = [str(recs)]
            else:
                purpose = "Evaluated via host triage baseline."
                risk = "Benign"
                reasoning = "No elevated risk factors detected."
                recs = []

            evaluated_procs.append(
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

        return TriageReport(
            hygiene_score=score,
            overall_risk=overall_risk,
            summary=summary,
            evaluated_processes=evaluated_procs,
            host_recommendations=host_recs,
            mode="ai",
            model_used=self.model,
            total_inspected=total_inspected,
            noise_filtered_count=noise_filtered_count,
            candidate_count=len(candidate_processes),
            anomalies_detected_count=total_anomalies,
            persistence_findings=persistence_findings,
        )
