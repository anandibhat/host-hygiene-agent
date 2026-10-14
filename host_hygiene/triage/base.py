"""Triage data models and base interface with enriched telemetry schema."""

from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from ..collector.base import ProcessInfo
from ..detector.anomaly_engine import AnomalyFinding


@dataclass
class ProcessTriageEvaluation:
    """Triage evaluation for an individual process with enriched forensic context."""
    pid: int
    process_name: str
    purpose: str                        # What does this software normally do?
    risk_rating: str                    # Benign, Suspicious, or Malicious
    reasoning: str
    actionable_recommendations: List[str] = field(default_factory=list)
    anomaly_findings: List[Dict[str, Any]] = field(default_factory=list)
    path: Optional[str] = None
    parent: Optional[Dict[str, Any]] = None
    command_line: Optional[str] = None
    sha256: Optional[str] = None
    user: Optional[str] = None
    signature: Dict[str, Any] = field(default_factory=dict)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    classification: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Format conforming to the enriched JSON reporting schema."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "path": self.path,
            "parent": self.parent if self.parent is not None else {"pid": 0, "name": "unknown"},
            "command_line": self.command_line,
            "sha256": self.sha256,
            "user": self.user,
            "signature": self.signature,
            "network_connections": self.network_connections,
            "classification": self.classification,
            "purpose": self.purpose,
            "risk_rating": self.risk_rating,
            "reasoning": self.reasoning,
            "actionable_recommendations": self.actionable_recommendations,
            "anomaly_findings": self.anomaly_findings,
        }


@dataclass
class TriageReport:
    """Consolidated host hygiene assessment and triage report."""
    hygiene_score: int                  # 0 to 100
    overall_risk: str                  # Benign, Suspicious, Elevated, or Critical
    summary: str
    evaluated_processes: List[ProcessTriageEvaluation]
    host_recommendations: List[str]
    mode: str                          # 'ai' or 'offline_fallback'
    model_used: Optional[str] = None
    total_inspected: int = 0
    noise_filtered_count: int = 0
    candidate_count: int = 0
    anomalies_detected_count: int = 0
    persistence_findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hygiene_score": self.hygiene_score,
            "overall_risk": self.overall_risk,
            "summary": self.summary,
            "mode": self.mode,
            "model_used": self.model_used,
            "total_inspected": self.total_inspected,
            "noise_filtered_count": self.noise_filtered_count,
            "candidate_count": self.candidate_count,
            "anomalies_detected_count": self.anomalies_detected_count,
            "host_recommendations": self.host_recommendations,
            "persistence_findings": self.persistence_findings,
            "evaluated_processes": [p.to_dict() for p in self.evaluated_processes],
        }


class BaseTriageEngine(ABC):
    """Abstract interface for process triage."""

    @abstractmethod
    def triage(
        self,
        candidate_processes: List[ProcessInfo],
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        total_inspected: int,
        noise_filtered_count: int,
        platform_name: str,
        persistence_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> TriageReport:
        pass
