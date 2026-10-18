"""Host Hygiene Agent Orchestrator: Inspects, filters, detects anomalies, and triages host processes."""

import argparse
import sys
import os
from typing import Optional, List, Dict, Any, Iterable

from .collector.base import ProcessInfo, BaseProcessCollector
from .collector.factory import CollectorFactory
from .collector.persistence import PersistenceAuditor
from .baseline.cache import BaselineCache
from .baseline.os_filter import OSBaselineFilter, BaselineFilterResult
from .detector.anomaly_engine import AnomalyDetectionEngine, AnomalyFinding
from .triage.base import TriageReport, BaseTriageEngine
from .triage.ai_triage import AITriageEngine
from .triage.offline_triage import OfflineTriageEngine
from .reporter.console import ConsoleReporter
from .reporter.json_exporter import JSONExporter


class HostHygieneAgent:
    """End-to-end host hygiene evaluation agent."""

    def __init__(
        self,
        platform_override: Optional[str] = None,
        custom_whitelist: Optional[Iterable[str]] = None,
        custom_whitelist_file: Optional[str] = None,
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-flash",
        force_offline: bool = False,
        cache_file: Optional[str] = None,
    ):
        self.cache = BaselineCache(cache_file=cache_file)
        self.collector: BaseProcessCollector = CollectorFactory.get_collector(
            platform_override=platform_override,
            cache=self.cache,
        )
        self.platform_name = self.collector.get_platform_name()

        # Baseline filter with persistent cache & OEM profiling
        self.baseline_filter = OSBaselineFilter(
            custom_whitelist=custom_whitelist,
            cache=self.cache,
        )
        if custom_whitelist_file:
            self.baseline_filter.load_custom_baseline_file(custom_whitelist_file)

        # Anomaly detection engine
        self.anomaly_engine = AnomalyDetectionEngine(platform_name=self.platform_name)

        # Triage engine
        if force_offline:
            self.triage_engine: BaseTriageEngine = OfflineTriageEngine()
        else:
            self.triage_engine = AITriageEngine(
                api_key=api_key,
                model=model,
                offline_fallback=True,
            )

    def run_hygiene_assessment(
        self,
        mock_processes: Optional[List[ProcessInfo]] = None,
        skip_persistence: bool = False,
    ) -> tuple[TriageReport, Dict[int, List[AnomalyFinding]]]:
        """Execute full host hygiene lifecycle.

        1. Data Collection (without external binary dependencies)
        2. Noise Reduction (OS baseline filter)
        3. Anomaly Detection (typosquatting, homoglyphs, IOCs)
        4. AI or Offline Triage
        """
        # Step 1: Collect processes
        processes = (
            mock_processes
            if mock_processes is not None
            else self.collector.collect()
        )

        # Step 2: Persistence Auditing
        persistence_findings: List[Dict[str, Any]] = []
        if not skip_persistence:
            try:
                persistence_findings = PersistenceAuditor.audit()
            except Exception:
                persistence_findings = []

        # Step 3: Noise Reduction via OS baseline filter & OEM profiles
        filter_result: BaselineFilterResult = self.baseline_filter.filter_processes(
            processes, self.platform_name
        )

        # Step 4: Anomaly Detection on candidates
        anomalies_by_pid: Dict[int, List[AnomalyFinding]] = self.anomaly_engine.analyze_processes(
            filter_result.candidate_processes
        )

        # Step 5: Triage (AI with offline fallback)
        report: TriageReport = self.triage_engine.triage(
            candidate_processes=filter_result.candidate_processes,
            anomalies_by_pid=anomalies_by_pid,
            total_inspected=filter_result.total_inspected,
            noise_filtered_count=filter_result.noise_filtered_count,
            platform_name=self.platform_name,
            persistence_findings=persistence_findings,
        )

        # Step 6: Save cache updates
        if self.cache:
            try:
                self.cache.save()
            except Exception:
                pass

        return report, anomalies_by_pid


def main():
    """Command-line entry point for the Host Hygiene Agent."""
    parser = argparse.ArgumentParser(
        description="Lightweight Cross-Platform Host Hygiene Agent in Python"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Force offline rule-based triage fallback (do not call LLM API)",
    )
    parser.add_argument(
        "--cache-file",
        type=str,
        default=None,
        help="Path to custom baseline_cache.json file",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Gemini API Key (default: GEMINI_API_KEY environment variable)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gemini-2.5-flash",
        help="Gemini model name (default: gemini-2.5-flash)",
    )
    parser.add_argument(
        "--platform",
        type=str,
        default=None,
        choices=["windows", "linux", "darwin"],
        help="Force target OS platform for simulation/testing",
    )
    parser.add_argument(
        "--whitelist",
        type=str,
        nargs="*",
        default=[],
        help="Additional custom process names to include in baseline whitelist",
    )
    parser.add_argument(
        "--whitelist-file",
        type=str,
        default=None,
        help="Path to JSON file with additional whitelist entries",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Path to save full hygiene report in JSON format",
    )
    parser.add_argument(
        "--min-score-fail",
        type=int,
        default=0,
        help="Exit with non-zero code if hygiene score is below this threshold (0-100)",
    )

    args = parser.parse_args()

    agent = HostHygieneAgent(
        platform_override=args.platform,
        custom_whitelist=args.whitelist,
        custom_whitelist_file=args.whitelist_file,
        api_key=args.api_key,
        model=args.model,
        force_offline=args.offline,
        cache_file=args.cache_file,
    )

    try:
        ConsoleReporter.print_banner()
        report, anomalies_by_pid = agent.run_hygiene_assessment()
        ConsoleReporter.render_report(report, agent.platform_name, anomalies_by_pid)

        if args.json_out:
            JSONExporter.export(
                report=report,
                platform_name=agent.platform_name,
                anomalies_by_pid=anomalies_by_pid,
                output_file=args.json_out,
            )
            print(f"Report exported to: {args.json_out}")

        if report.hygiene_score < args.min_score_fail:
            print(
                f"\nCompliance Failure: Hygiene score {report.hygiene_score} "
                f"below threshold {args.min_score_fail}."
            )
            sys.exit(1)
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)


if __name__ == "__main__":
    main()
