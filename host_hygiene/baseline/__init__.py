"""Baseline and noise reduction package."""

from .cache import BaselineCache
from .os_filter import OSBaselineFilter, BaselineFilterResult
from .oem_profiles import classify_hardware_or_oem
from .signatures import (
    WINDOWS_BASELINE,
    LINUX_BASELINE,
    DARWIN_BASELINE,
    PROTECTED_CORE_NAMES,
)

__all__ = [
    "BaselineCache",
    "OSBaselineFilter",
    "BaselineFilterResult",
    "classify_hardware_or_oem",
    "WINDOWS_BASELINE",
    "LINUX_BASELINE",
    "DARWIN_BASELINE",
    "PROTECTED_CORE_NAMES",
]
