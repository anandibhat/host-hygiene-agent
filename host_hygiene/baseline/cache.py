"""Persistent Local Baseline Cache: Stores trusted (path, sha256) pairs and signature metadata."""

import json
import os
import time
from typing import Dict, Any, Optional

DEFAULT_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "daily_reports",
    "baseline_cache.json",
)


class BaselineCache:
    """Manages local cache of verified binaries and known signatures."""

    def __init__(self, cache_file: Optional[str] = None):
        self.cache_file = cache_file or DEFAULT_CACHE_FILE
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}
        else:
            self._cache = {}

    def save(self) -> None:
        try:
            cache_dir = os.path.dirname(self.cache_file)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def get(self, path: str, sha256: Optional[str]) -> Optional[Dict[str, Any]]:
        """Retrieve cached signature and classification for a path and matching sha256."""
        if not path or not sha256:
            return None
        norm_path = path.lower()
        entry = self._cache.get(norm_path)
        if entry and entry.get("sha256") == sha256:
            return entry
        return None

    def set(
        self,
        path: str,
        sha256: str,
        signature: Dict[str, Any],
        classification: Optional[str] = None,
    ) -> None:
        """Cache a verified binary."""
        if not path or not sha256:
            return
        norm_path = path.lower()
        self._cache[norm_path] = {
            "path": path,
            "sha256": sha256,
            "signature": signature,
            "classification": classification,
            "cached_at": time.time(),
        }
