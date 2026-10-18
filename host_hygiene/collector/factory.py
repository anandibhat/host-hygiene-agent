"""Collector Factory for instantiating the appropriate OS process collector."""

import sys
from typing import Optional, Any

from .base import BaseProcessCollector
from .windows import WindowsProcessCollector
from .linux import LinuxProcessCollector
from .darwin import DarwinProcessCollector


class CollectorFactory:
    """Factory to obtain the platform-appropriate process collector."""

    @staticmethod
    def get_collector(
        platform_override: Optional[str] = None,
        cache: Optional[Any] = None,
    ) -> BaseProcessCollector:
        """Instantiate a process collector based on platform.

        Args:
            platform_override: Force platform ('windows', 'linux', 'darwin').
            cache: Optional BaselineCache for persistent caching.
        """
        plat = (platform_override or sys.platform).lower()

        if "darwin" in plat or "mac" in plat:
            return DarwinProcessCollector(cache=cache)
        elif "win" in plat:
            return WindowsProcessCollector(cache=cache)
        elif "linux" in plat:
            return LinuxProcessCollector(cache=cache)
        else:
            # Fallback to linux/proc-based or posix
            return LinuxProcessCollector(cache=cache)
