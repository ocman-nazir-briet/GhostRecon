"""
Pipeline — runs registered plugins in dependency order.

The old main.py ran every phase strictly one-after-another even when
nothing forced that ordering (e.g. subdomain enumeration and port-scan
recon don't depend on each other at all, but were coded sequentially).
The pipeline instead builds "waves" from each plugin's `depends_on` list —
every plugin in a wave has all its dependencies satisfied by earlier waves —
and runs everything within a wave concurrently with asyncio.gather. This
generally makes multi-module scans (--subdomains --dirbrute --screenshot)
noticeably faster, and adding a new plugin never requires touching this file.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List

from core.context import ScanContext
from core.plugin import Plugin, PluginResult
from core.registry import PluginRegistry


@dataclass
class PipelineReport:
    ran: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    errors: dict = field(default_factory=dict)
    results: dict = field(default_factory=dict)
    total_duration: float = 0.0


class Pipeline:
    def __init__(self, registry: PluginRegistry, ctx: ScanContext):
        self.registry = registry
        self.ctx = ctx

    def _selected_plugins(self) -> List[Plugin]:
        """Instantiate every registered plugin, then keep the ones enabled
        for this engagement (per CLI flags via ctx.flags)."""
        all_plugins = self.registry.instantiate_all()
        return [p for p in all_plugins if p.enabled(self.ctx)]

    async def run(self, on_phase_start=None, on_phase_done=None, on_wave_start=None,
                  between_waves=None) -> PipelineReport:
        """
        on_wave_start(wave_index, plugins)  — called before a wave of
                                               (potentially concurrent) plugins starts
        on_phase_start(plugin)              — called right before a plugin runs
        on_phase_done(plugin, result)       — called right after a plugin finishes
        between_waves()                     — optional async hook awaited between
                                               waves (e.g. a stealth-mode delay)
        All are optional hooks for CLI progress display; the pipeline
        itself has no UI opinions.
        """
        selected = self._selected_plugins()
        waves = self.registry.resolve_order(selected)

        report = PipelineReport()
        disabled = set(self.registry.names()) - {p.name for p in selected}
        report.skipped = sorted(disabled)

        loop_start = asyncio.get_event_loop().time()

        for wave_index, wave in enumerate(waves):
            if on_wave_start:
                on_wave_start(wave_index, wave)
            async def _run_one(plugin: Plugin):
                if on_phase_start:
                    on_phase_start(plugin)
                result = await plugin.run_timed(self.ctx)
                if on_phase_done:
                    on_phase_done(plugin, result)
                return plugin, result

            # Plugins in the same wave have no dependency on each other,
            # so they can safely run concurrently.
            outcomes = await asyncio.gather(*[_run_one(p) for p in wave])
            for plugin, result in outcomes:
                report.ran.append(plugin.name)
                report.results[plugin.name] = result
                if result.error:
                    report.errors[plugin.name] = result.error

            if between_waves and wave_index < len(waves) - 1:
                await between_waves()

        report.total_duration = asyncio.get_event_loop().time() - loop_start
        return report
