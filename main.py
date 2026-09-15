#!/usr/bin/env python3
# Force UTF-8 output before any other imports (Windows cp1252 compatibility)
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
"""
GhostRecon v2.0.0 — Main CLI

Thin CLI driver: parses arguments, builds a ScanContext, and hands
execution to core.pipeline.Pipeline, which runs whatever plugins are
registered (see core/bootstrap.py) in dependency order. main.py itself no
longer knows about any individual scan module — adding a new plugin never
requires touching this file.

Usage:
  python main.py --target 10.0.0.1 --mode pentest
  python main.py --target example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 192.168.1.1 --mode pentest --ai --api-key sk-ant-... --output ./reports
"""

import asyncio
import os
import time
import random
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from core.orchestrator import EngagementState, Mode
from core.config import load_settings, Settings
from core.context import ScanContext
from core.pipeline import Pipeline
from core.registry import registry
import core.bootstrap  # noqa: F401 — importing this registers every plugin
from utils.logger import get_logger

console = Console(legacy_windows=False)

BANNER = """
[bold green]
  ____ _   _  ___  ____ _____ ____  _____ ____ ___  _   _
 / ___| | | |/ _ \\/ ___|_   _|  _ \\| ____/ ___/ _ \\| \\ | |
| |  _| |_| | | | \\___ \\ | | | |_) |  _|| |  | | | |  \\| |
| |_| |  _  | |_| |___) || | |  _ <| |__| |__| |_| | |\\  |
 \\____|_| |_|\\___/|____/ |_| |_| \\_\\_____\\____\\___/|_| \\_|
[/bold green][dim]  GhostRecon v2.0.0 -- plugin-based recon & vulnerability scanner[/dim]
[red]  For authorized security testing only[/red]
"""

SEVERITY_STYLE = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "blue", "info": "dim",
}

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
]


def print_banner():
    console.print(BANNER)
    console.print(Rule(style="dim"))


def print_phase_header(phase: str, icon: str = "◆"):
    console.print(f"\n[bold cyan]{icon} {phase.upper()}[/bold cyan]")
    console.print(Rule(style="cyan dim"))


def print_open_ports_table(state: EngagementState):
    if not state.recon_data.get("open_ports"):
        return
    t = Table(box=box.SIMPLE, padding=(0, 1), show_header=True, header_style="dim")
    t.add_column("Port", width=6)
    t.add_column("Service", width=14)
    t.add_column("Banner", min_width=30)
    for port, info in sorted(state.recon_data["open_ports"].items()):
        t.add_row(str(port), info["service"], (info.get("banner", "") or "—")[:50])
    console.print(t)


def print_findings_table(state: EngagementState):
    if not state.findings:
        console.print("[dim]  No findings yet[/dim]")
        return
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Title", min_width=40)
    table.add_column("MITRE", style="dim", width=10)
    table.add_column("Phase", style="dim", width=8)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(state.findings, key=lambda x: sev_order.get(x.severity.value, 5)):
        style = SEVERITY_STYLE.get(f.severity.value, "")
        tactic = f.mitre_tactic[:8] + ".." if len(f.mitre_tactic) > 10 else f.mitre_tactic
        table.add_row(
            Text(f.severity.value.upper(), style=style),
            f.title[:60], tactic, f.phase,
        )
    console.print(table)


def print_summary_panel(state: EngagementState):
    counts = state.finding_counts()

    def bar(n, total, color):
        pct = int((n / max(total, 1)) * 20)
        return f"[{color}]{'#' * pct}{'.' * (20 - pct)}[/{color}] {n}"

    total = sum(counts.values())
    opsec_color = "green" if state.opsec_score >= 70 else "yellow" if state.opsec_score >= 40 else "red"
    content = (
        f"[bold]Target:[/bold]  {state.target}\n"
        f"[bold]Mode:[/bold]    {state.mode.value.upper()}\n"
        f"[bold]Duration:[/bold] {state.elapsed()}\n"
        f"[bold]OPSEC:[/bold]   [{opsec_color}]{state.opsec_score}/100[/{opsec_color}]\n\n"
        f"[bold red]CRITICAL[/bold red] {bar(counts.get('critical',0), total, 'red')}\n"
        f"[red]HIGH    [/red] {bar(counts.get('high',0), total, 'red')}\n"
        f"[yellow]MEDIUM  [/yellow] {bar(counts.get('medium',0), total, 'yellow')}\n"
        f"[blue]LOW     [/blue] {bar(counts.get('low',0), total, 'blue')}\n"
        f"[dim]INFO    [/dim] {bar(counts.get('info',0), total, 'white')}\n\n"
        f"[bold]Total:[/bold] {total} findings"
    )
    console.print(Panel(content, title="[bold]Engagement Summary[/bold]", border_style="cyan"))


async def stealth_delay(settings: Settings):
    """Apply a random delay between pipeline waves in stealth mode."""
    delay = random.uniform(settings.stealth.min_delay, settings.stealth.max_delay)
    await asyncio.sleep(delay)


async def run_engagement(
    target: str,
    mode: str,
    api_key: str = None,
    output_dir: str = "./reports",
    enable_ai: bool = False,
    stealth: bool = False,
    interactive: bool = False,
    enable_subdomains: bool = False,
    enable_screenshots: bool = False,
    config_path: str = None,
    no_report: bool = False,
    enable_dirbrute: bool = False,
    enable_pdf: bool = False,
    deep: bool = False,
    shodan_key: str = None,
):
    print_banner()
    settings = load_settings(config_path)

    if output_dir == "./reports":
        output_dir = settings.paths.reports or output_dir

    state = EngagementState(target=target, mode=Mode(mode), scope=[target], opsec_score=100)
    struct_logger = get_logger()
    struct_logger.info(f"Engagement start: target={target} mode={mode} stealth={stealth}")

    mode_color = "green" if mode == "pentest" else "red"
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   [{mode_color}]{mode.upper()}[/{mode_color}]\n"
        f"[bold]Stealth:[/bold] {'[green]ON[/green]' if stealth else '[dim]OFF[/dim]'}\n"
        f"[bold]Time:[/bold]   {time.strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold]Engagement Start[/bold]",
        border_style=mode_color,
    ))
    ghost_engine_path = settings.paths.ghost_engine or "(not configured — using built-in fallback scanner)"
    console.print(f"  [green]✓[/green] Config loaded | Ghost Engine: {ghost_engine_path}")
    enabled_plugins = sorted(p.name for p in registry.instantiate_all())
    console.print(f"  [dim]Plugins registered: {len(enabled_plugins)} ({', '.join(enabled_plugins)})[/dim]")

    flags = {
        "stealth": stealth,
        "deep": deep,
        "subdomains": enable_subdomains,
        "dirbrute": enable_dirbrute,
        "screenshot": enable_screenshots,
        "ai": enable_ai,
        "pdf": enable_pdf,
        "no_report": no_report,
        "shodan_key": shodan_key,
        "output_dir": output_dir,
        "interactive": interactive,
    }
    ctx = ScanContext(state=state, settings=settings, console=console,
                      logger=struct_logger, flags=flags, api_key=api_key)

    def on_wave_start(wave_index, wave):
        names = ", ".join(p.display_name for p in wave)
        print_phase_header(f"Wave {wave_index + 1} — {names}", "◆")
        if stealth:
            console.print("  [yellow]⚡ Stealth mode: slow scan, UA rotation, random delays[/yellow]")

    def on_phase_start(plugin):
        console.print(f"  [cyan]▶ {plugin.display_name}...[/cyan]")

    def on_phase_done(plugin, result):
        if result.error:
            console.print(f"  [bold red]✗[/bold red] {plugin.display_name} failed: {result.error}")
            struct_logger.warning(f"Plugin {plugin.name} failed: {result.error}")
            return
        for line in result.summary:
            console.print(f"  [green]✓[/green] {line}")
        struct_logger.info(f"Plugin {plugin.name} completed in {result.duration:.2f}s")

        if plugin.name == "recon":
            print_open_ports_table(ctx.state)
            if interactive:
                console.input("\n[dim]  Press Enter to continue to next phase...[/dim]")
        elif plugin.name == "msf_bridge":
            mapped = [f for f in ctx.state.findings if getattr(f, "msf_module", "")]
            if mapped:
                from modules.msf_bridge import print_msf_table
                print_msf_table(ctx.state, console)

    async def between_waves():
        if stealth:
            await stealth_delay(settings)

    pipeline = Pipeline(registry, ctx)
    pipeline_report = await pipeline.run(
        on_phase_start=on_phase_start,
        on_phase_done=on_phase_done,
        on_wave_start=on_wave_start,
        between_waves=between_waves,
    )

    if pipeline_report.skipped:
        console.print(f"\n[dim]Skipped (not enabled for this run): {', '.join(pipeline_report.skipped)}[/dim]")

    # Belt-and-suspenders: ensure findings are deduped for the console table
    # even if --no-report skipped the report plugin (which also dedupes).
    state.dedupe_findings()

    console.print()
    print_summary_panel(state)
    console.print("\n[bold]All Findings:[/bold]")
    print_findings_table(state)

    report_result = pipeline_report.results.get("report")
    paths = report_result.data if (report_result and not report_result.error) else {}
    if no_report:
        console.print("\n[dim]Report skipped (--no-report)[/dim]")

    console.print()
    console.print(Rule(style="green"))
    counts = state.finding_counts()
    if counts.get("critical", 0) > 0:
        risk = "CRITICAL"
    elif counts.get("high", 0) > 0:
        risk = "HIGH"
    elif counts.get("medium", 0) > 0:
        risk = "MEDIUM"
    elif counts.get("low", 0) > 0:
        risk = "LOW"
    elif counts.get("info", 0) > 0:
        risk = "INFO"
    else:
        risk = "NONE"
    console.print(
        f"[bold green]Engagement complete.[/bold green] "
        f"Risk: [bold red]{risk}[/bold red] | "
        f"{sum(counts.values())} findings | "
        f"OPSEC: {state.opsec_score}/100 | "
        f"Pipeline: {pipeline_report.total_duration:.1f}s"
    )
    console.print("[dim]For authorized security testing only.[/dim]")
    console.print()

    struct_logger.info(
        f"Engagement complete: target={target} risk={risk} "
        f"findings={sum(counts.values())} duration={pipeline_report.total_duration:.1f}s"
    )

    return state, paths


def main():
    parser = argparse.ArgumentParser(
        description="GhostRecon v2.0.0 — Web fingerprinting & security analysis\nFor authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py 10.0.0.1
  python main.py example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 10.0.0.1 --mode pentest --ai --api-key sk-ant-...
  python main.py --target 192.168.1.1 --mode pentest --ai --output ./reports
        """
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Target IP or hostname (positional)")
    parser.add_argument("--target", "-t", dest="target_flag", default=None,
                        help="Target IP or hostname (flag form)")
    parser.add_argument("--mode", "-m", choices=["pentest", "redteam"], default="pentest")
    parser.add_argument("--ai", action="store_true",
                        help="Enable Claude AI analysis (requires --api-key or ANTHROPIC_API_KEY)")
    parser.add_argument("--api-key", "-k", help="Anthropic API key (or ANTHROPIC_API_KEY env var)")
    parser.add_argument("--output", "-o", default="./reports", help="Output directory")
    parser.add_argument("--output-dir", dest="output_dir", default=None, help="Output directory (alias)")
    parser.add_argument("--stealth", action="store_true",
                        help="Enable stealth mode (delays, UA rotation)")
    parser.add_argument("--interactive", action="store_true", help="Pause between phases")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--screenshot", action="store_true",
                        help="Enable screenshots (requires playwright)")
    parser.add_argument("--config", default=None, help="Config file path (YAML)")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--dirbrute", action="store_true", help="Enable directory brute-force")
    parser.add_argument("--pdf", action="store_true", help="Export report as PDF")
    parser.add_argument("--shodan-key", dest="shodan_key", default=None,
                         help="Shodan API key to enrich recon with host data (or SHODAN_API_KEY env var)")
    parser.add_argument("--deep", action="store_true",
                         help="Deep discovery mode: use the 250k+ endpoint / 150k+ subdomain "
                              "permutation wordlists (config/wordlists/*_large.txt) instead of "
                              "the curated defaults, with higher concurrency. Combine with "
                              "--subdomains and/or --dirbrute.")
    parser.add_argument("--list-plugins", action="store_true",
                         help="List registered plugins and exit")

    args = parser.parse_args()

    if args.list_plugins:
        for name in sorted(registry.names()):
            cls = registry.get(name)
            print(f"{name:16s} phase={cls.phase.value:10s} depends_on={cls.depends_on}")
        sys.exit(0)

    target = args.target or args.target_flag
    if not target:
        parser.error(
            "target is required: pass it as a positional argument or via --target/-t\n"
            "  e.g.  ghostrecon example.com\n"
            "  e.g.  ghostrecon --target example.com"
        )

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    output_dir = args.output_dir or args.output

    if args.ai and not api_key:
        parser.error(
            "--ai flag requires --api-key or the ANTHROPIC_API_KEY environment variable.\n"
            "  Set it with:  --api-key sk-ant-...\n"
            "  Or export:    set ANTHROPIC_API_KEY=sk-ant-..."
        )

    try:
        asyncio.run(run_engagement(
            target=target,
            mode=args.mode,
            api_key=api_key,
            output_dir=output_dir,
            enable_ai=args.ai,
            stealth=args.stealth,
            interactive=args.interactive,
            enable_subdomains=args.subdomains,
            enable_screenshots=args.screenshot,
            config_path=args.config,
            no_report=args.no_report,
            enable_dirbrute=args.dirbrute,
            deep=args.deep,
            enable_pdf=args.pdf,
            shodan_key=shodan_key,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
