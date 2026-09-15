# Changelog

All notable changes to GhostRecon are documented here.

---

## [2.0.0] — 2026-09-15

### Added — plugin architecture rewrite
- `core/plugin.py` — `Plugin` base class: every scan capability now declares `name`,
  `phase`, `depends_on` and `enabled(ctx)` instead of being a bare function main.py called
  by hand
- `core/registry.py` — self-registration via `@register`, plus dependency-graph
  resolution into ordered "waves" (topological sort; raises on circular dependencies;
  ignores dependencies on plugins disabled for the current run)
- `core/pipeline.py` — executes each wave's plugins concurrently with `asyncio.gather`
  instead of the old strictly-sequential phase list, with `on_wave_start` /
  `on_phase_start` / `on_phase_done` / `between_waves` hooks for CLI progress display and
  stealth-mode pacing
- `core/context.py` — a single `ScanContext` (state + settings + console + structured
  logger + CLI flags) passed to every plugin, replacing per-module bespoke argument lists
- `core/config.py` — typed, layered `pydantic` settings: defaults → `config.yaml` →
  `GHOSTRECON_*` environment variables → CLI flags, with real validation instead of a
  silently-merged dict
- `core/bootstrap.py` — the single place that imports every plugin module to trigger
  registration
- All 14 scan modules converted to registered plugins: `recon`, `subdomain`, `web`,
  `jwt_analyzer`, `fingerprint`, `default_creds`, `dirbrute`, `waf_bypass`,
  `shodan_recon`, `cve`, `msf_bridge`, `screenshot`, `opsec`, `ai_engine`, plus report
  generation itself as a `report` plugin
- `--shodan-key` flag (and `SHODAN_API_KEY` env var) — the Shodan enrichment module
  existed in the codebase but was never wired into the CLI; it's now a live plugin
- WAF bypass payload generation (`modules/waf_bypass.py`) — also previously implemented
  but never invoked — now runs automatically whenever web analysis has data
- `--list-plugins` — prints the registered plugins, phases and dependency graph
- `utils/logger.py` (credential-masking structured file logger) is now actually wired
  into the CLI — it existed but was never imported anywhere before
- `EngagementState.dedupe_findings()` — the finding-deduplication logic that used to be
  350 lines inline in `main.py`'s `run_engagement()` is now a state method, called once
  by the `report` plugin and once defensively in `main.py` for `--no-report` runs
- `tests/test_pipeline.py` — registry, dependency-resolution, wave-execution and
  layered-config tests for the new core

### Changed
- `main.py` shrank from one 662-line function that hard-coded every phase to a thin CLI
  driver: parse args → build `Settings`/`ScanContext` → `Pipeline.run()` → print summary.
  Adding a new plugin never requires editing `main.py` again.
- Independent phases that were previously sequential now run concurrently (e.g. recon and
  subdomain enumeration, or web analysis / fingerprinting / default-creds / dirbrute after
  recon), generally shortening multi-flag scans
- CLI flags are unchanged — this is an internal rewrite, not a breaking change to how you
  invoke `ghostrecon`

---

## [1.1.0] — 2026-09-15

### Added
- `--deep` CLI flag: switches directory brute-force and subdomain enumeration to large
  permutation-based wordlists instead of the curated defaults
- `config/wordlists/endpoints_large.txt` — 250,000+ generated candidate paths
- `config/wordlists/subdomains_large.txt` — 150,000+ generated candidate labels
- `scripts/generate_wordlists.py` — regenerates the large wordlists from a seed list +
  system dictionary, with a configurable target size
- Chunked scanning (5,000 candidates per batch) and higher concurrency in deep mode
  (200 for dirbrute, 300 for DNS) so hundreds of thousands of candidates stay practical
  to scan without exhausting memory or open connections

### Changed
- Project rebranded to GhostRecon

---

## [1.0.0] — 2026-04-24

### Added
- Ghost Engine scanner integration (35+ tech fingerprints, WAF detection, vuln checks, CVE)
- `modules/subdomain.py` — async DNS brute-force, 500+ wordlist, 50 concurrent
- `modules/screenshot.py` — Playwright headless Chromium screenshots, base64 HTML embed
- `modules/waf_bypass.py` — WAF-specific payloads for XSS/SQLi/LFI/XXE/SSRF/RCE
- `modules/opsec.py` — OPSEC scoring 0–100 with NINJA/GHOST/NOISY/LOUD/BUSTED ratings
- `modules/cve.py` — NVD API v2.0 + Ghost Engine CVE lookup, 7-day JSON cache
- `modules/default_creds.py` — FTP/SSH/HTTP/Telnet default credential testing (T1078)
- `modules/msf_bridge.py` — automatic finding → Metasploit module mapping
- `modules/shodan_recon.py` — Shodan host enrichment via direct REST API
- `modules/dirbrute.py` — async directory brute-force, 20 concurrent, WAF rate-limit handling
- `modules/jwt_analyzer.py` — JWT alg:none, weak HS256, RS256→HS256 confusion, expiry (T1550.001)
- `output/pdf_export.py` — PDF via WeasyPrint or print-CSS fallback
- `utils/logger.py` — credential-masking file logger
- `modules/ghost_engine_bridge.py` — Ghost Engine integration bridge
- New AD checks: LDAP anonymous bind, SMB null session, MS17-010, Kerberos pre-auth, BloodHound
- HTML report: dark mode, CVE table, OPSEC timeline, kill chain diagram, print CSS
- CLI flags: `--stealth`, `--interactive`, `--subdomains`, `--screenshot`, `--dirbrute`,
  `--shodan-key`, `--pdf`, `--config`, `--output-dir`, `--no-report`, `--api-key`
- `config/config.yaml` configuration file
- Wordlists: 500+ subdomains, 200+ endpoints, top-100 passwords
- `setup.bat` (Windows) and `setup.sh` (Kali/Linux) setup scripts
- `setup.py` + `pyproject.toml` for `pip install -e .` and `ghostrecon` global command
- `.github/workflows/ci.yml` — Python 3.11/3.12/3.13 CI matrix
- Banner subtitle changed to "by the GhostRecon Project" with `[bold green]` color
- Version v1.0.0 added to banner

### Changed
- CVE lookup now skips technologies with no detected version (prevents false positives)
- OPSEC bonus cap raised to 120 before clamping to allow pre-deduction buffers
- Report generator: XSS-safe HTML escaping for all user-controlled content

---

*For authorized security testing only.*
