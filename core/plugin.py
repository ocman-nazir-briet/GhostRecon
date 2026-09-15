"""
Plugin base class for GhostRecon scan modules.

Every scan capability (recon, web analysis, dirbrute, CVE correlation, ...)
is implemented as a Plugin subclass with declared metadata: which phase it
belongs to, which other plugins it depends on (so the pipeline can run
independent plugins concurrently and dependent ones in order), and whether
it should run for a given engagement (based on CLI flags / config).

This replaces the old model where main.py hard-coded a linear sequence of
`await run_x(state, console)` calls with no way to know what depended on
what, and no way to add a new capability without editing main.py.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from core.orchestrator import EngagementState, Phase


@dataclass
class PluginResult:
    """What a plugin hands back to the pipeline after running."""
    data: Any = None
    summary: list = field(default_factory=list)   # human-readable lines for the console
    error: Optional[str] = None
    duration: float = 0.0


class Plugin:
    """
    Base class for a GhostRecon scan plugin.

    Subclasses set class attributes:
      name          — unique registry key, e.g. "recon", "dirbrute"
      display_name  — shown in phase headers, e.g. "Reconnaissance"
      phase         — a core.orchestrator.Phase grouping (for reporting/UX)
      depends_on    — list of plugin `name`s that must complete first
      icon          — single character/emoji shown in the phase header

    And implement:
      enabled(ctx)  — return True if this plugin should run for this engagement
      async run(ctx) -> PluginResult
    """

    name: str = ""
    display_name: str = ""
    phase: Phase = Phase.RECON
    depends_on: list = []
    icon: str = "◆"

    def enabled(self, ctx: "ScanContext") -> bool:  # noqa: F821 (see context.py)
        return True

    async def run(self, ctx: "ScanContext") -> PluginResult:  # noqa: F821
        raise NotImplementedError

    async def run_timed(self, ctx: "ScanContext") -> PluginResult:  # noqa: F821
        """Wraps run() with timing + error capture so one bad plugin can't
        take down the whole engagement."""
        start = time.time()
        try:
            result = await self.run(ctx)
            if result is None:
                result = PluginResult()
            result.duration = time.time() - start
            return result
        except Exception as exc:  # noqa: BLE001 — plugins must never crash the pipeline
            return PluginResult(error=str(exc), duration=time.time() - start)

    def __repr__(self) -> str:
        return f"<Plugin {self.name} phase={self.phase.value} depends_on={self.depends_on}>"
