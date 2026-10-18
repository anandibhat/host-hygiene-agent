"""Noise Reduction: OS & Hardware Baseline Filter for standard OS and OEM components."""

import json
import os
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Iterable

from ..collector.base import ProcessInfo
from .signatures import (
    WINDOWS_BASELINE,
    LINUX_BASELINE,
    LINUX_KERNEL_THREAD_PREFIXES,
    DARWIN_BASELINE,
)
from .oem_profiles import classify_hardware_or_oem
from .cache import BaselineCache
from ..collector.signature import SignatureVerifier


@dataclass
class BaselineFilterResult:
    """Outcome of filtering processes through the OS and OEM baselines."""
    baseline_processes: List[ProcessInfo]
    candidate_processes: List[ProcessInfo]
    total_inspected: int
    noise_filtered_count: int
    noise_reduction_ratio: float  # 0.0 to 1.0


class OSBaselineFilter:
    """Filters out standard OS components and trusted OEM/hardware profile binaries."""

    def __init__(
        self,
        custom_whitelist: Optional[Iterable[str]] = None,
        cache: Optional[BaselineCache] = None,
    ):
        self._custom_whitelist: Set[str] = set()
        self.cache = cache
        if custom_whitelist:
            for item in custom_whitelist:
                self._custom_whitelist.add(item.lower().strip())

    def add_to_whitelist(self, item: str) -> None:
        self._custom_whitelist.add(item.lower().strip())

    def load_custom_baseline_file(self, file_path: str) -> None:
        """Load additional baseline process names from a JSON file."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Baseline file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    self._custom_whitelist.add(str(item).lower().strip())
            elif isinstance(data, dict) and "whitelist" in data:
                for item in data["whitelist"]:
                    self._custom_whitelist.add(str(item).lower().strip())

    def is_baseline(self, process: ProcessInfo, platform_name: str) -> bool:
        """Determines if a process is a recognized standard OS or trusted OEM component."""
        name_lower = process.name.lower().strip()
        clean = process.clean_name

        # 1. Check user custom whitelist
        if name_lower in self._custom_whitelist or clean in self._custom_whitelist:
            if not process.classification:
                process.classification = "Whitelist:Custom"
            return True

        # 2. Check persistent local baseline cache (path + sha256 match)
        if self.cache and process.path and process.sha256:
            cached = self.cache.get(process.path, process.sha256)
            if cached:
                if not process.classification:
                    process.classification = cached.get("classification") or "Cached:Baseline"
                return True

        # 3. Check Hardware & OEM Profiles (ThinkPad/Lenovo, Intel Core Ultra, DevTools)
        oem_class = classify_hardware_or_oem(clean)
        if oem_class:
            process.classification = oem_class
            # If signed by a trusted publisher, auto-classify as legitimate baseline
            sig = process.signature or {}
            publisher = sig.get("publisher", "")
            if SignatureVerifier.is_trusted_publisher(publisher) or sig.get("status") == "VALID":
                return True

        # 4. Check if signed by Microsoft / Windows / Apple in standard OS directories
        sig = process.signature or {}
        sig_valid = sig.get("status") == "VALID"
        pub = sig.get("publisher", "").lower()
        if sig_valid:
            if "microsoft" in pub or "lenovo" in pub or "intel" in pub:
                if process.path and (
                    "\\windows\\" in process.path.lower()
                    or "\\program files\\" in process.path.lower()
                    or "\\program files (x86)\\" in process.path.lower()
                ):
                    if not process.classification:
                        process.classification = "VerifiedVendor:System"
                    return True
            if "apple" in pub:
                if not process.classification:
                    process.classification = "VerifiedVendor:Apple"
                return True

        # 4b. Platform-specific path-based baseline filtering (protected system directories)
        plat = platform_name.lower()
        if "darwin" in plat or "mac" in plat:
            if process.path:
                p_lower = process.path.lower()
                if (
                    p_lower.startswith("/system/")
                    or p_lower.startswith("/usr/libexec/")
                    or p_lower.startswith("/usr/sbin/")
                    or p_lower.startswith("/library/apple/")
                ):
                    if not process.classification:
                        process.classification = "OS:Darwin (System Path)"
                    return True
        elif "linux" in plat:
            if process.path:
                p_lower = process.path.lower()
                if (
                    p_lower.startswith("/lib/systemd/")
                    or p_lower.startswith("/usr/lib/systemd/")
                ):
                    if not process.classification:
                        process.classification = "OS:Linux (System Path)"
                    return True

        # 5. OS-specific baseline signatures
        if "darwin" in plat or "mac" in plat:
            if name_lower in DARWIN_BASELINE or clean in DARWIN_BASELINE:
                if not process.classification:
                    process.classification = "OS:Darwin"
                return True
            return False

        elif "win" in plat:
            if (
                name_lower in WINDOWS_BASELINE
                or f"{clean}.exe" in WINDOWS_BASELINE
                or clean in WINDOWS_BASELINE
            ):
                if not process.classification:
                    process.classification = "OS:Windows"
                return True
            return False

        elif "linux" in plat:
            if name_lower in LINUX_BASELINE or clean in LINUX_BASELINE:
                if not process.classification:
                    process.classification = "OS:Linux"
                return True
            for prefix in LINUX_KERNEL_THREAD_PREFIXES:
                if name_lower.startswith(prefix):
                    if not process.classification:
                        process.classification = "Kernel:Thread"
                    return True
            return False

        # Fallback union
        return (
            name_lower in WINDOWS_BASELINE
            or name_lower in LINUX_BASELINE
            or name_lower in DARWIN_BASELINE
        )

    def filter_processes(
        self, processes: List[ProcessInfo], platform_name: str
    ) -> BaselineFilterResult:
        """Filter the collected processes into baseline background noise and candidate processes."""
        baseline_list: List[ProcessInfo] = []
        candidate_list: List[ProcessInfo] = []

        for proc in processes:
            if self.is_baseline(proc, platform_name):
                baseline_list.append(proc)
            else:
                candidate_list.append(proc)

        total = len(processes)
        filtered = len(baseline_list)
        ratio = (filtered / total) if total > 0 else 0.0

        return BaselineFilterResult(
            baseline_processes=baseline_list,
            candidate_processes=candidate_list,
            total_inspected=total,
            noise_filtered_count=filtered,
            noise_reduction_ratio=ratio,
        )
