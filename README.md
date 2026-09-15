<div align="center">

```
  ____ _   _  ___  ____ _____ ____  _____ ____ ___  _   _
 / ___| | | |/ _ \/ ___|_   _|  _ \| ____/ ___/ _ \| \ | |
| |  _| |_| | | | \___ \ | | | |_) |  _|| |  | | | |  \| |
| |_| |  _  | |_| |___) || | |  _ <| |__| |__| |_| | |\  |
 \____|_| |_|\___/|____/ |_| |_| \_\_____\____\___/|_| \_|
```

**Plugin-based recon & vulnerability scanner**
*For authorized security testing only*

[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success)](#)

</div>

---

# GhostRecon

GhostRecon is a command-line reconnaissance and vulnerability-triage tool for
authorized security assessments. Point it at a host or domain and it runs a
coordinated set of checks — open ports, TLS posture, HTTP security headers,
exposed endpoints, outdated JavaScript libraries, known CVEs, default
credentials, JWT weaknesses — and hands back a single HTML/JSON report with
everything ranked by severity.

It is not a wrapper around one technique. Internally it's a small dependency
graph of independent scan plugins that the engine schedules for you, which is
also what makes it straightforward to extend (see [Under the hood](#under-the-hood)).

> **Authorized use only.** Run this only against systems you own or are
> explicitly contracted to test. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Getting started

```bash
git clone https://github.com/your-username/GhostRecon
cd GhostRecon
pip install -r requirements.txt
pip install -e .
```

Windows users can run `setup.bat` instead of the two `pip` commands above;
Kali/Debian users can run `chmod +x setup.sh && ./setup.sh`.

Then point it at something you're allowed to scan:

```bash
ghostrecon example.com
```

That's a baseline pass: port scan, header/cookie/TLS analysis, technology
fingerprinting, CVE correlation, and an HTML + JSON report in `./reports`.
Everything else — subdomain brute-forcing, directory discovery, screenshots,
AI-written summaries, Shodan enrichment — is opt-in via flags, covered below.

```text
$ ghostrecon cytex.io --mode redteam --subdomains --screenshot --dirbrute --pdf

  ____ _   _  ___  ____ _____ ____  _____ ____ ___  _   _
 / ___| | | |/ _ \/ ___|_   _|  _ \| ____/ ___/ _ \| \ | |
| |  _| |_| | | | \___ \ | | | |_) |  _|| |  | | | |  \| |
| |_| |  _  | |_| |___) || | |  _ <| |__| |__| |_| | |\  |
 \____|_| |_|\___/|____/ |_| |_| \_\_____\____\___/|_| \_|
  GhostRecon v2.0.0 -- plugin-based recon & vulnerability scanner
  For authorized security testing only
```

---

## What a scan actually does

A run is built out of independent stages that only run when their inputs are
ready, so unrelated stages overlap instead of queuing behind each other:

1. **Reconnaissance** — DNS resolution and a concurrent port sweep (18 ports
   by default, more in `--stealth`), identifying which ports are actually
   serving HTTP(S). Subdomain brute-forcing (`--subdomains`) happens at the
   same time, since it doesn't need anything from the port scan.
2. **Surface analysis** — once recon knows which ports talk HTTP, several
   things happen against them at once: security-header and cookie auditing,
   SQLi/XSS probing, email harvesting, technology fingerprinting (50+
   signatures across servers, CMSes, frameworks, analytics and CDNs), a
   default-credentials check, and — if you asked for it — directory
   brute-forcing and Shodan host enrichment.
3. **Correlation** — detected technology versions get checked against known
   CVEs and cross-referenced with Metasploit module names where a match
   exists; JWTs seen in responses get checked for `alg:none`, weak HS256
   secrets, and algorithm-confusion attacks; WAF-specific bypass payloads are
   generated if a WAF was fingerprinted.
4. **Scoring and reporting** — an OPSEC score (how noisy the engagement was)
   is computed from what actually ran, an optional Claude-generated executive
   summary and attack narrative is attached (`--ai`), and everything is
   deduplicated and written out as a dark-themed HTML report plus a JSON
   export (and a PDF, with `--pdf`).

---

## Command reference

**Target & engagement**

| Flag | Purpose |
|---|---|
| `target` (positional) or `--target`/`-t` | Host or domain to scan |
| `--mode`, `-m` | `pentest` (default, business-risk framing) or `redteam` (stealth/MITRE framing) |
| `--stealth` | Randomized delays + user-agent rotation, wider port list |
| `--interactive` | Pause for confirmation after recon before continuing |

**Discovery add-ons**

| Flag | Purpose |
|---|---|
| `--subdomains` | Brute-force subdomains via DNS resolution |
| `--dirbrute` | Brute-force HTTP paths for exposed admin panels, backups, configs, etc. |
| `--deep` | Swap the curated wordlists (~300 paths / ~600 subdomain labels) for generated permutation lists — 250,000+ paths and 150,000+ subdomain candidates — with concurrency raised accordingly. See `scripts/generate_wordlists.py` to regenerate or resize them. |
| `--screenshot` | Capture a headless-Chromium screenshot of each web service |
| `--shodan-key` | Enrich recon with Shodan host data (or set `SHODAN_API_KEY`) |

**Analysis & output**

| Flag | Purpose |
|---|---|
| `--ai` | Attach a Claude-generated executive summary and attack narrative (needs `--api-key` or `ANTHROPIC_API_KEY`) |
| `--api-key`, `-k` | Anthropic API key |
| `--output`, `-o` | Report output directory (default `./reports`) |
| `--pdf` | Also export the report as a PDF |
| `--no-report` | Run the scan without writing a report |
| `--config` | Path to a custom `config.yaml` |
| `--list-plugins` | Print the registered plugins and their dependency graph, then exit |

**A few combinations:**

```bash
ghostrecon example.com --mode redteam --stealth --subdomains --dirbrute
ghostrecon example.com --ai --api-key sk-ant-...
ghostrecon example.com --dirbrute --subdomains --deep
ghostrecon 10.0.0.7 --shodan-key $SHODAN_API_KEY --pdf
```

---

## Under the hood

Every capability — recon, web analysis, dirbrute, CVE correlation, AI
analysis, the report itself — is a `Plugin` that registers itself with a
central registry and declares two things: what it depends on, and whether it
should run at all for the current flags. At scan time, `core/pipeline.py`
topologically sorts whichever plugins are enabled into **waves** — everything
in a wave has its dependencies already satisfied by an earlier wave, so it
all runs concurrently with `asyncio.gather` instead of waiting in a fixed
line. A `--subdomains --ai` run resolves to something like:

```
wave 1 → recon, subdomain
wave 2 → web, fingerprint, default_creds, dirbrute*, shodan_recon*
wave 3 → jwt_analyzer, waf_bypass, cve, screenshot*
wave 4 → msf_bridge
wave 5 → opsec
wave 6 → ai_engine*
wave 7 → report
```
(`*` = only present when its flag or key was supplied.)

Configuration follows the same layering everywhere: built-in defaults →
`config.yaml` → `GHOSTRECON_*` environment variables → CLI flags, validated
through `pydantic` models (`core/config.py`) instead of a loosely-typed dict.
Every plugin receives one `ScanContext` (`core/context.py`) carrying the
scan state, resolved settings, console, and structured logger, and every
run leaves an audit trail in `logs/engagement_*.log` with per-plugin timing
and credential-masked output.

Run `ghostrecon --list-plugins` any time to see exactly what's registered.

---

## Writing a plugin

Extending GhostRecon means adding one file, not touching the CLI. A minimal
plugin looks like:

```python
from core.plugin import Plugin, PluginResult
from core.orchestrator import Phase
from core.registry import register

@register
class MyCheckPlugin(Plugin):
    name = "my_check"
    display_name = "My Custom Check"
    phase = Phase.WEB
    depends_on = ["recon"]        # runs once recon's data is available

    def enabled(self, ctx) -> bool:
        return ctx.flag("my_check")   # gated by a --my-check style flag

    async def run(self, ctx) -> PluginResult:
        # ctx.state is the shared EngagementState; ctx.settings, ctx.console,
        # ctx.logger, and ctx.flags are all available here too.
        ...
        return PluginResult(data={...}, summary=["My check: found 3 things"])
```

Register the module in `core/bootstrap.py` so it's imported (which triggers
`@register`), and the pipeline will schedule it automatically wherever the
dependency graph puts it — no changes to `main.py` required.

---

## Configuration

`config/config.yaml` holds defaults for anything you don't want to pass as a
flag every time:

```yaml
scan:
  timeout: 2.0
  max_parallel_ports: 50

ai:
  model: "claude-sonnet-4-6"
  max_tokens: 2000

stealth:
  min_delay: 1.0
  max_delay: 3.0
  rotate_ua: true

paths:
  wordlists: "./config/wordlists"
  reports: "./reports"
```

Anything here can also be overridden with an environment variable
(`GHOSTRECON_REPORTS_DIR`, `GHOSTRECON_AI_MODEL`, `GHOSTRECON_SCAN_TIMEOUT`,
...) which take precedence over the file but not over an explicit CLI flag.

---

## Legal

This project is for authorized security testing, CTFs, and research — not
for scanning systems you don't have permission to test. Unauthorized use can
violate computer-crime law in most jurisdictions (CFAA in the US, the
Computer Misuse Act in the UK, Directive 2013/40/EU, and equivalents
elsewhere). Full terms are in [DISCLAIMER.md](DISCLAIMER.md).

## License

MIT — see [LICENSE](LICENSE).