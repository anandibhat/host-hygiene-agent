"""Host Hygiene Agent package."""

from .agent import HostHygieneAgent, main
from .collector.base import ProcessInfo, BaseProcessCollector
from .collector.factory import CollectorFactory
from .baseline.os_filter import OSBaselineFilter, BaselineFilterResult
from .detector.anomaly_engine import AnomalyDetectionEngine, AnomalyFinding
from .triage.base import TriageReport, ProcessTriageEvaluation
from .triage.ai_triage import AITriageEngine
from .triage.offline_triage import OfflineTriageEngine
from .reporter.console import ConsoleReporter
from .reporter.json_exporter import JSONExporter

__version__ = "1.0.0"

__all__ = [
    "HostHygieneAgent",
    "main",
    "ProcessInfo",
    "BaseProcessCollector",
    "CollectorFactory",
    "OSBaselineFilter",
    "BaselineFilterResult",
    "AnomalyDetectionEngine",
    "AnomalyFinding",
    "TriageReport",
    "ProcessTriageEvaluation",
    "AITriageEngine",
    "OfflineTriageEngine",
    "ConsoleReporter",
    "JSONExporter",
]
