"""
Tests for the plugin architecture: core/plugin.py, core/registry.py,
core/pipeline.py, core/config.py.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.plugin import Plugin, PluginResult
from core.registry import PluginRegistry
from core.pipeline import Pipeline
from core.context import ScanContext
from core.config import Settings
from core.orchestrator import EngagementState, Mode, Phase


def make_ctx():
    state = EngagementState(target="example.com", mode=Mode.PENTEST)
    return ScanContext(state=state, settings=Settings(), console=None, logger=None, flags={})


# ── registry / dependency resolution ─────────────────────────────────────────

def test_register_and_lookup():
    reg = PluginRegistry()

    @reg.register
    class A(Plugin):
        name = "a"

    assert reg.get("a") is A
    assert reg.names() == ["a"]


def test_duplicate_name_rejected():
    reg = PluginRegistry()

    @reg.register
    class A(Plugin):
        name = "dup"

    with pytest.raises(ValueError):
        @reg.register
        class B(Plugin):
            name = "dup"


def test_resolve_order_respects_dependencies():
    reg = PluginRegistry()

    @reg.register
    class First(Plugin):
        name = "first"
        depends_on = []

    @reg.register
    class Second(Plugin):
        name = "second"
        depends_on = ["first"]

    @reg.register
    class Independent(Plugin):
        name = "independent"
        depends_on = []

    plugins = reg.instantiate_all()
    waves = reg.resolve_order(plugins)

    wave_names = [sorted(p.name for p in wave) for wave in waves]
    # "first" and "independent" have no deps -> same wave; "second" waits.
    assert wave_names[0] == ["first", "independent"]
    assert wave_names[1] == ["second"]


def test_resolve_order_ignores_missing_dependency():
    """A dependency on a plugin that wasn't selected for this run (e.g. a
    disabled optional plugin) must not block the graph."""
    reg = PluginRegistry()

    @reg.register
    class Needs(Plugin):
        name = "needs"
        depends_on = ["never_selected"]

    plugins = reg.instantiate_all()
    waves = reg.resolve_order(plugins)
    assert [p.name for wave in waves for p in wave] == ["needs"]


def test_circular_dependency_raises():
    reg = PluginRegistry()

    @reg.register
    class A(Plugin):
        name = "a"
        depends_on = ["b"]

    @reg.register
    class B(Plugin):
        name = "b"
        depends_on = ["a"]

    with pytest.raises(RuntimeError):
        reg.resolve_order(reg.instantiate_all())


# ── enabled()-based selection ─────────────────────────────────────────────────

def test_disabled_plugin_is_skipped():
    reg = PluginRegistry()

    @reg.register
    class OnlyIfFlag(Plugin):
        name = "flagged"

        def enabled(self, ctx):
            return ctx.flag("turn_it_on")

    ctx = make_ctx()
    pipeline = Pipeline(reg, ctx)
    selected = pipeline._selected_plugins()
    assert selected == []

    ctx.flags["turn_it_on"] = True
    selected = pipeline._selected_plugins()
    assert [p.name for p in selected] == ["flagged"]


# ── pipeline execution ────────────────────────────────────────────────────────

def test_pipeline_runs_waves_and_collects_results():
    reg = PluginRegistry()
    order_log = []

    @reg.register
    class StepA(Plugin):
        name = "step_a"
        depends_on = []

        async def run(self, ctx):
            order_log.append("a")
            return PluginResult(data={"x": 1}, summary=["step a done"])

    @reg.register
    class StepB(Plugin):
        name = "step_b"
        depends_on = ["step_a"]

        async def run(self, ctx):
            order_log.append("b")
            assert ctx.state is not None
            return PluginResult(data={"y": 2}, summary=["step b done"])

    ctx = make_ctx()
    pipeline = Pipeline(reg, ctx)
    report = asyncio.run(pipeline.run())

    assert order_log == ["a", "b"]
    assert report.ran == ["step_a", "step_b"]
    assert report.results["step_a"].data == {"x": 1}
    assert report.results["step_b"].data == {"y": 2}
    assert report.errors == {}


def test_pipeline_captures_plugin_exception_without_crashing():
    reg = PluginRegistry()

    @reg.register
    class Boom(Plugin):
        name = "boom"

        async def run(self, ctx):
            raise ValueError("kaboom")

    @reg.register
    class Fine(Plugin):
        name = "fine"

        async def run(self, ctx):
            return PluginResult(data="ok")

    ctx = make_ctx()
    pipeline = Pipeline(reg, ctx)
    report = asyncio.run(pipeline.run())

    assert "kaboom" in report.errors["boom"]
    assert report.results["fine"].data == "ok"


def test_hooks_are_called():
    reg = PluginRegistry()

    @reg.register
    class Step(Plugin):
        name = "step"

        async def run(self, ctx):
            return PluginResult(summary=["done"])

    starts, dones, waves = [], [], []
    ctx = make_ctx()
    pipeline = Pipeline(reg, ctx)
    asyncio.run(pipeline.run(
        on_phase_start=lambda p: starts.append(p.name),
        on_phase_done=lambda p, r: dones.append((p.name, r.summary)),
        on_wave_start=lambda i, wave: waves.append([p.name for p in wave]),
    ))

    assert starts == ["step"]
    assert dones == [("step", ["done"])]
    assert waves == [["step"]]


# ── config layering ────────────────────────────────────────────────────────────

def test_settings_defaults():
    s = Settings()
    assert s.scan.timeout == 2.0
    assert s.stealth.rotate_ua is True
    assert s.paths.reports == "./reports"


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("GHOSTRECON_REPORTS_DIR", "/tmp/custom_reports")
    s = Settings().apply_env_overrides()
    assert s.paths.reports == "/tmp/custom_reports"
