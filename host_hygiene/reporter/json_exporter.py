"""JSON Exporter for Host Hygiene Reports."""

import json
from typing import Dict, Any, List

from ..triage.base import TriageReport
from ..detector.anomaly_engine import AnomalyFinding


class JSONExporter:
    """Exports host hygiene reports and anomalies to standard JSON format."""

    @staticmethod
    def export(
        report: TriageReport,
        platform_name: str,
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        output_file: str,
        indent: int = 2,
    ) -> None:
        payload = report.to_dict()
        payload["platform"] = platform_name
        payload["all_anomalies"] = [
            f.to_dict()
            for findings in anomalies_by_pid.values()
            for f in findings
        ]

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=indent)

    @staticmethod
    def to_json_str(
        report: TriageReport,
        platform_name: str,
        anomalies_by_pid: Dict[int, List[AnomalyFinding]],
        indent: int = 2,
    ) -> str:
        payload = report.to_dict()
        payload["platform"] = platform_name
        payload["all_anomalies"] = [
            f.to_dict()
            for findings in anomalies_by_pid.values()
            for f in findings
        ]
        return json.dumps(payload, indent=indent)
