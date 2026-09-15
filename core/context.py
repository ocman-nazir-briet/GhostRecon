"""
ScanContext — everything a plugin needs to do its job, in one object.

Before this, every module function took its own bespoke subset of
arguments (`state, console, stealth=..., deep=..., ghost_engine_path=...`),
which meant adding a new setting meant touching every module's signature.
Plugins now take a single `ctx: ScanContext` and pull out whatever they need.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from core.orchestrator import EngagementState
from core.config import Settings


@dataclass
class ScanContext:
    state: EngagementState
    settings: Settings
    console: Any = None          # rich.console.Console, or None for silent/headless runs
    logger: Any = None           # utils.logger structured logger
    flags: dict = field(default_factory=dict)   # CLI-derived toggles, e.g. {"deep": True}
    api_key: Optional[str] = None

    def flag(self, name: str, default: bool = False) -> bool:
        return bool(self.flags.get(name, default))

    def log(self, msg: str) -> None:
        """Console progress line (rich markup) + structured file log, best-effort."""
        if self.console:
            self.console.print(f"  [dim]→[/dim] {msg}")
        if self.logger:
            try:
                # Strip rich markup crudely for the plain-text log file.
                import re
                plain = re.sub(r"\[/?[a-zA-Z0-9 _]*\]", "", msg)
                self.logger.info(plain)
            except Exception:
                pass
