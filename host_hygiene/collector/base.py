"""Base interface and enriched data models for process collection."""

from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any


@dataclass
class ProcessInfo:
    """Represents an active running process with enriched forensic telemetry."""
    pid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent: Optional[Dict[str, Any]] = None  # {"pid": int, "name": str}
    user: Optional[str] = None
    sha256: Optional[str] = None
    signature: Dict[str, Any] = field(
        default_factory=lambda: {"status": "UNVERIFIED", "publisher": ""}
    )
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    classification: Optional[str] = None  # "OS:Windows", "OEM:Lenovo", "OEM:Intel", "DevTools"
    extra: Dict[str, Any] = field(default_factory=dict)

    # Backwards compatibility properties
    @property
    def ppid(self) -> Optional[int]:
        if self.parent and "pid" in self.parent:
            return self.parent["pid"]
        return None

    @property
    def cmdline(self) -> Optional[str]:
        return self.command_line

    @property
    def username(self) -> Optional[str]:
        return self.user

    @property
    def clean_name(self) -> str:
        """Normalized lowercase name stripped of path and extension for comparison."""
        base = self.name.lower().strip()
        if base.endswith(".exe"):
            base = base[:-4]
        return base

    def to_dict(self) -> Dict[str, Any]:
        """Format matching the enriched forensic JSON reporting schema."""
        return {
            "pid": self.pid,
            "process_name": self.name,
            "path": self.path,
            "parent": self.parent if self.parent is not None else {"pid": 0, "name": "unknown"},
            "command_line": self.command_line,
            "sha256": self.sha256,
            "user": self.user,
            "signature": self.signature,
            "network_connections": self.network_connections,
            "classification": self.classification,
        }


class BaseProcessCollector(ABC):
    """Abstract base class for platform-specific process collectors."""

    @abstractmethod
    def collect(self) -> List[ProcessInfo]:
        """Collect active running processes without external binary dependencies.

        Returns:
            List of ProcessInfo objects with enriched telemetry.
        """
        pass

    @abstractmethod
    def get_platform_name(self) -> str:
        """Returns the platform identifier: 'windows', 'darwin', or 'linux'."""
        pass
