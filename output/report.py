"""
Report Generator — dark cybersecurity dashboard HTML/JSON report.

Produces a single self-contained HTML file (no external assets, no CDN
dependencies): a sidebar-navigated, searchable findings dashboard with an
SVG severity donut, an auto-generated executive summary, and every recon
data set the engagement collected. output/pdf_export.py turns this exact
page into a PDF via a headless-Chromium render.
"""

import json
import math
import os
import re
from datetime import datetime
from core.orchestrator import EngagementState, Severity

# ── Palette ───────────────────────────────────────────────────────────────────
C = {
    "bg":       "#0a0e1a",
    "bg2":      "#080b14",
    "card":     "#0d1117",
    "card2":    "#0f1923",
    "border":   "#1e2d40",
    "border2":  "#263a52",
    "green":    "#00ff88",
    "cyan":     "#0ea5e9",
    "purple":   "#a78bfa",
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#3b82f6",
    "info":     "#6b7280",
    "text":     "#e6edf3",
    "muted":    "#8b949e",
    "dim":      "#3d4f61",
}

SEV_COLOR = {
    "critical": C["critical"],
    "high":     C["high"],
    "medium":   C["medium"],
    "low":      C["low"],
    "info":     C["info"],
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

ICON = {
    "overview":          "🛰",
    "executive-summary": "📋",
    "ai-summary":        "🧠",
    "kill-chain":        "⛓",
    "screenshots":       "🖼",
    "real-ip":           "🌐",
    "technologies":      "🧬",
    "emails":            "✉",
    "subdomains":        "🗂",
    "ports":             "📡",
    "credentials":       "🔓",
    "cve":               "🧾",
    "dirbrute":          "🧭",
    "msf":               "🗡",
    "findings":          "⚠",
    "ad-chain":          "🏰",
    "opsec":             "📈",
    "notes":             "📝",
}


# ── Small helpers ─────────────────────────────────────────────────────────────

def _escape(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _glow(color: str, spread: int = 8) -> str:
    return f"0 0 {spread}px {color}66, 0 0 {spread*2}px {color}33"


def _sev_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, C["info"])
    return (
        f'<span class="badge" style="color:{color};background:{color}22;'
        f'border-color:{color}55;box-shadow:{_glow(color,6)}">{sev}</span>'
    )


def _ring_chart(segments, size=132, stroke=14, cap="butt") -> str:
    """Multi-segment circular ring chart as inline SVG — no JS/CSS dependency,
    so it renders identically in the browser, WeasyPrint and the Playwright
    PDF path."""
    r = (size - stroke) / 2
    cx = cy = size / 2
    circumference = 2 * math.pi * r
    total = sum(v for v, _ in segments)
    arcs = ""
    offset = 0.0
    if total > 0:
        for value, color in segments:
            if value <= 0:
                continue
            seg_len = (value / total) * circumference
            arcs += (
                f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="{color}" '
                f'stroke-width="{stroke}" stroke-linecap="{cap}" '
                f'stroke-dasharray="{seg_len:.2f} {circumference - seg_len:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}"/>'
            )
            offset += seg_len
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<g transform="rotate(-90 {cx} {cy})">'
        f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="{C["border"]}" stroke-width="{stroke}"/>'
        f'{arcs}</g></svg>'
    )


def _panel(section_id: str, title: str, inner: str, count=None, subtitle: str = "",
           extra: str = "", title_color: str = None) -> str:
    icon = ICON.get(section_id, "▶")
    count_badge = f'<span class="count-badge">{count}</span>' if count is not None else ""
    subtitle_html = f'<p class="panel-sub">{subtitle}</p>' if subtitle else ""
    color_style = f' style="color:{title_color}"' if title_color else ""
    return (
        f'<section class="panel" id="{section_id}">'
        f'<div class="panel-head"><h2 class="panel-title"{color_style}>'
        f'<span class="panel-icon">{icon}</span>{_escape(title)}{count_badge}{extra}</h2></div>'
        f'{subtitle_html}{inner}'
        f'</section>'
    )


def _bar_row(label: str, count: int, color: str, total: int) -> str:
    pct = int((count / max(total, 1)) * 100)
    return (
        f'<div class="bar-row">'
        f'<div class="bar-row-head"><span class="bar-row-label" style="color:{color}">{label}</span>'
        f'<span class="bar-row-count">{count}</span></div>'
        f'<div class="bar-track"><div class="bar-fill" '
        f'style="background:linear-gradient(90deg,{color},{color}88);box-shadow:0 0 8px {color}88" '
        f'data-w="{pct}"></div></div></div>'
    )


# ── Section content builders (return inner HTML only — _panel adds the chrome) ─

def _screenshot_section(screenshots: dict) -> str:
    items = ""
    for port, ss in screenshots.items():
        if ss.get("error") or not ss.get("base64"):
            continue
        url = _escape(ss.get("url", f"Port {port}"))
        b64 = ss["base64"]
        items += (
            f'<div class="screenshot-item">'
            f'<div class="screenshot-bar"><span style="color:{C["green"]}">$</span> screenshot :: {url}</div>'
            f'<img src="data:image/png;base64,{b64}" loading="lazy" alt="Screenshot {url}"></div>'
        )
    return items


def _cve_table_section(cve_data: dict) -> str:
    cves = cve_data.get("cves", [])
    if not cves:
        return ""
    rows = ""
    for cve in cves[:30]:
        score = cve.get("cvss_score", 0)
        sev = cve.get("severity", "LOW").lower()
        cve_id = _escape(cve.get("cve_id", ""))
        ref = _escape(cve.get("reference_url", "#"))
        tech = _escape(cve.get("technology", ""))
        desc = _escape(cve.get("description", ""))[:120]
        fixed = _escape(cve.get("fixed_version", "N/A"))
        rows += (
            f'<tr class="trow">'
            f'<td><a href="{ref}" target="_blank" rel="noopener" class="mono" '
            f'style="color:{C["cyan"]};text-decoration:none;font-size:12px">{cve_id}</a></td>'
            f'<td class="mono muted" style="font-size:12px">{tech}</td>'
            f'<td>{_sev_badge(sev)} <span class="mono muted" style="font-size:11px;margin-left:4px">{score}</span></td>'
            f'<td class="muted" style="font-size:12px">{desc}</td>'
            f'<td class="mono" style="font-size:11px;color:{C["green"]}">{fixed}</td>'
            f'</tr>'
        )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>CVE ID</th><th>Technology</th><th>Severity / CVSS</th>'
        '<th>Description</th><th>Fixed In</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _technologies_section(technologies: list) -> str:
    if not technologies:
        return ""
    cat_order = {"Server": 0, "Language": 1, "CMS": 2, "Framework": 3, "Library": 4}
    sorted_techs = sorted(
        technologies,
        key=lambda t: (cat_order.get(t.get("category", ""), 9), t.get("name", "").lower())
    )
    conf_color = {"high": C["green"], "medium": C["medium"], "low": C["muted"]}
    rows = ""
    for t in sorted_techs:
        name = _escape(t.get("name", ""))
        version = _escape(t.get("version", ""))
        conf = t.get("confidence", "low")
        category = _escape(t.get("category", ""))
        evidence = _escape(t.get("evidence", ""))
        color = conf_color.get(conf, C["muted"])
        ver_badge = (
            f'<span class="mini-badge" style="color:{C["cyan"]};background:{C["cyan"]}22;'
            f'border-color:{C["cyan"]}44;margin-left:6px">{version}</span>'
        ) if version else ""
        conf_badge = f'<span class="badge" style="color:{color};background:{color}22;border-color:{color}44">{conf}</span>'
        rows += (
            f'<tr class="trow"><td style="font-weight:700">{name}{ver_badge}</td>'
            f'<td class="mono" style="font-size:12px;color:{C["cyan"]}">{category}</td>'
            f'<td>{conf_badge}</td>'
            f'<td class="mono muted" style="font-size:11px">{evidence}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>Technology</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _emails_section(emails: list) -> str:
    if not emails:
        return ""
    items = "".join(
        f'<span class="chip"><a href="mailto:{_escape(e)}" style="color:{C["cyan"]};text-decoration:none">{_escape(e)}</a></span>'
        for e in emails[:60]
    )
    extra = (
        f'<div class="mono muted" style="font-size:11px;margin-top:8px">// {len(emails)-60} more addresses not shown</div>'
    ) if len(emails) > 60 else ""
    return f'<div class="chip-row">{items}</div>{extra}'


def _subdomain_section(sub_found: list) -> str:
    if not sub_found:
        return ""
    items = "".join(f'<span class="chip" style="color:{C["cyan"]}">{_escape(s)}</span>' for s in sub_found[:50])
    extra = (
        f'<div class="mono muted" style="font-size:11px;margin-top:8px">// {len(sub_found)-50} more not shown</div>'
    ) if len(sub_found) > 50 else ""
    return f'<div class="chip-row">{items}</div>{extra}'


def _real_ip_section(real_ips: list) -> str:
    if not real_ips:
        return ""
    conf_color = {"confirmed": C["green"], "high": C["critical"], "medium": C["medium"], "low": C["low"]}
    rows = ""
    for entry in real_ips:
        ip = _escape(entry.get("ip", ""))
        method = _escape(entry.get("method", ""))
        conf = entry.get("confidence", "low")
        country = _escape(entry.get("country", ""))
        last_seen = _escape(entry.get("last_seen", ""))
        verified = entry.get("verified", False)
        color = conf_color.get(conf, C["info"])
        verified_badge = (
            f'<span class="mini-badge" style="color:{C["green"]};background:{C["green"]}22;'
            f'border-color:{C["green"]}44;margin-left:6px">✓ verified</span>'
        ) if verified else ""
        rows += (
            f'<tr class="trow"><td class="mono" style="font-weight:700;color:{C["green"]}">{ip}{verified_badge}</td>'
            f'<td class="mono" style="font-size:12px;color:{C["cyan"]}">{method}</td>'
            f'<td><span class="badge" style="color:{color};background:{color}22;border-color:{color}55">{conf}</span></td>'
            f'<td class="muted" style="font-size:12px">{country}</td>'
            f'<td class="mono muted" style="font-size:11px">{last_seen}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>IP Address</th><th>Discovery Method</th><th>Confidence</th>'
        '<th>Country</th><th>Last Seen</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _ports_section(open_ports: dict) -> str:
    if not open_ports:
        return ""
    rows = ""
    for port, info in sorted(open_ports.items()):
        banner = _escape((info.get("banner", "") or "—")[:80])
        rows += (
            f'<tr class="trow"><td class="mono" style="font-weight:700;color:{C["green"]}">{port}</td>'
            f'<td class="mono" style="font-size:12px;color:{C["cyan"]}">{_escape(info["service"])}</td>'
            f'<td class="mono muted" style="font-size:11px">{banner}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _creds_section(default_creds_data: dict) -> str:
    vulnerable = default_creds_data.get("vulnerable", [])
    if not vulnerable:
        return ""
    rows = "".join(
        f'<tr class="trow"><td class="mono" style="color:{C["green"]}">{_escape(v["service"].upper())}:{_escape(str(v["port"]))}</td>'
        f'<td class="mono" style="color:{C["critical"]}">{_escape(v["username"])} : {_escape(v["password"])}</td></tr>'
        for v in vulnerable
    )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>Service</th><th>Credentials</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _dirbrute_section(dirbrute_data: dict) -> str:
    results = dirbrute_data.get("results", {})
    if not results:
        return ""
    rows = ""
    for port_key, entries in results.items():
        for e in entries[:20]:
            status = e.get("status", 0)
            status_color = (C["critical"] if status == 200 else C["medium"] if status in (401, 403) else C["muted"])
            rows += (
                '<tr class="trow">'
                f'<td class="mono" style="color:{C["green"]};font-size:12px">{_escape(e.get("url",""))}</td>'
                f'<td class="mono" style="font-weight:700;color:{status_color}">{status}</td>'
                f'<td class="mono muted" style="font-size:11px">{e.get("content_length","?")}</td>'
                '</tr>'
            )
    if not rows:
        return ""
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>URL</th><th>Status</th><th>Length</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _msf_section(msf_data: dict) -> str:
    modules = msf_data.get("modules", {})
    if not modules:
        return ""
    rows = "".join(
        f'<tr class="trow"><td class="mono" style="font-size:11px;color:{C["green"]}">{_escape(mod)}</td>'
        f'<td class="muted" style="font-size:12px">{", ".join(_escape(t) for t in titles[:2])}</td></tr>'
        for mod, titles in modules.items()
    )
    return (
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>MSF Module</th><th>Finding(s)</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _ad_section(ad_data: dict) -> str:
    if not (ad_data.get("ad_detected") and ad_data.get("attack_plan")):
        return ""
    items = ""
    for step in ad_data["attack_plan"]:
        chain = ad_data.get("attack_chains", {}).get(step["chain"], {})
        cmds = "".join(
            f'<div class="ad-cmd-line"><span class="muted">$ </span><span style="color:{C["green"]}">{_escape(c)}</span></div>'
            for c in chain.get("commands", [])
        )
        cmds_block = f'<div class="ad-cmds">{cmds}</div>' if cmds else ""
        items += (
            '<div class="ad-step"><div class="ad-step-head">'
            f'<span class="ad-step-num">STEP {step["step"]}</span>'
            f'<span class="ad-step-name">{_escape(step["name"])}</span>'
            f'<span class="ad-step-tech">{_escape(chain.get("technique",""))}</span>'
            '</div>'
            f'<p class="ad-step-reason">{_escape(step.get("reason",""))}</p>'
            f'{cmds_block}</div>'
        )
    return '<p class="panel-sub">Replace {domain} {user} {pass} {dc_ip} with real values.</p>' + items


def _opsec_timeline_section(opsec_data: dict, mode: str) -> str:
    if mode != "redteam" or not opsec_data:
        return ""
    events = opsec_data.get("events", [])
    score = opsec_data.get("score", 100)
    rating = opsec_data.get("rating", "N/A")
    score_color = C["green"] if score >= 70 else C["medium"] if score >= 40 else C["critical"]
    pct = max(0, min(100, score))
    ring = _ring_chart([(pct, score_color), (100 - pct, C["border"])], size=104, stroke=11)
    gauge = (
        '<div class="opsec-gauge"><div class="ring-wrap" style="width:104px;height:104px">'
        f'{ring}<div class="ring-center">'
        f'<div class="ring-num" style="color:{score_color};font-size:20px">{score}</div>'
        '<div class="ring-lbl">/100</div></div></div>'
        f'<div><div class="opsec-rating" style="color:{score_color}">{_escape(rating)}</div>'
        '<div class="opsec-rating-lbl">OPSEC Rating</div></div></div>'
    )
    rows = "".join(
        '<tr class="trow">'
        f'<td class="mono muted">{ev.get("timestamp",0):.1f}s</td>'
        f'<td>{_escape(ev.get("label",""))}</td>'
        f'<td class="mono" style="font-weight:700;color:{C["green"] if ev.get("delta",0)>0 else C["critical"]}">'
        f'{"+" + str(ev.get("delta",0)) if ev.get("delta",0) > 0 else ev.get("delta",0)}</td>'
        f'<td class="mono" style="font-weight:700">{ev.get("score_after",0)}</td>'
        '</tr>'
        for ev in events
    )
    table = (
        f'<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>Time</th><th>Event</th><th>Delta</th><th>Score</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    ) if rows else ""
    return gauge + table


def _kill_chain_section(state: EngagementState) -> str:
    phase_map = [
        ("recon",         "Recon",         "T1046"),
        ("subdomain",     "Subdomain",     "T1596"),
        ("web",           "Web Attack",    "T1190"),
        ("cve",           "CVE Exploit",   "T1190"),
        ("ad",            "AD Attack",     "T1558"),
        ("dirbrute",      "Dir Brute",     "T1083"),
        ("jwt",           "JWT Forge",     "T1550"),
        ("default_creds", "Cred Stuff",    "T1078"),
        ("report",        "Exfil/Report",  "T1041"),
    ]
    seen = set(f.phase for f in state.findings)
    nodes = ""
    for i, (key, label, tech) in enumerate(phase_map):
        active = key in seen
        color = C["green"] if active else C["dim"]
        glow = f"box-shadow:{_glow(C['green'],10)};" if active else ""
        arrow = '<span class="kc-arrow">→</span>' if i < len(phase_map) - 1 else ""
        nodes += (
            f'<div class="kc-node" style="border-color:{color};background:{color}22;{glow}">'
            f'<div class="kc-label" style="color:{color}">{label}</div>'
            f'<div class="kc-tech">{tech}</div></div>{arrow}'
        )
    return f'<div class="kc-track">{nodes}</div>'


def _notes_section(notes: list) -> str:
    lines = "".join(
        f'<div class="note-line"><span style="color:{C["green"]}">&gt; </span>{_escape(n)}</div>'
        for n in notes
    ) or f'<div class="mono" style="color:{C["dim"]};font-size:12px">// no notes</div>'
    return f'<div class="notes-box">{lines}</div>'


def _executive_summary(state: EngagementState, counts: dict, total: int, risk_label: str,
                        risk_color: str, cve_total: int, mode_label: str) -> str:
    bullets = []
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    med, low = counts.get("medium", 0), counts.get("low", 0)
    if total:
        bullets.append(f"{total} finding(s) identified — {crit} critical, {high} high, {med} medium, {low} low.")
    else:
        bullets.append("No findings were recorded during this engagement.")
    if cve_total:
        bullets.append(f"{cve_total} known CVE(s) correlated against fingerprinted technology versions.")
    creds = state.default_creds_data.get("vulnerable", [])
    if creds:
        bullets.append(f"{len(creds)} service(s) accepting default credentials.")
    subs = state.recon_data.get("subdomains", {}).get("found", [])
    if subs:
        bullets.append(f"{len(subs)} subdomain(s) discovered.")
    real_ips = state.recon_data.get("real_ips", [])
    if real_ips:
        bullets.append(f"{len(real_ips)} candidate origin IP address(es) found behind CDN/WAF.")
    shots = state.recon_data.get("screenshots", {})
    shot_ok = sum(1 for s in shots.values() if not s.get("error"))
    if shot_ok:
        bullets.append(f"{shot_ok} web service screenshot(s) captured for visual triage.")

    items = "".join(f"<li>{b}</li>" for b in bullets)
    lead = (
        f'<p class="exec-lead">This {_escape(mode_label.lower())} of '
        f'<span class="mono" style="color:{C["cyan"]}">{_escape(state.target)}</span> '
        f'concluded with an overall risk rating of <b style="color:{risk_color}">{_escape(risk_label)}</b>.</p>'
    )
    return f'{lead}<ul class="exec-list">{items}</ul>'


def _finding_cards(sorted_findings: list) -> str:
    parts = []
    prev_sev = None
    for i, f in enumerate(sorted_findings, 1):
        color = SEV_COLOR.get(f.severity.value, C["info"])

        if f.severity.value != prev_sev:
            prev_sev = f.severity.value
            grp_count = sum(1 for x in sorted_findings if x.severity.value == f.severity.value)
            grp_color = SEV_COLOR.get(f.severity.value, C["info"])
            parts.append(
                f'<div class="sev-divider" data-sevgroup="{f.severity.value}" '
                f'style="border-left-color:{grp_color};background:{grp_color}11">'
                f'<span class="sev-divider-label" style="color:{grp_color}">{f.severity.value}</span>'
                f'<span class="sev-divider-count">{grp_count} finding{"s" if grp_count != 1 else ""}</span>'
                '</div>'
            )

        msf_mod = getattr(f, "msf_module", "")
        msf_badge = (
            f'<span class="mini-badge" style="color:{C["green"]};background:{C["green"]}22;'
            f'border-color:{C["green"]}44;margin-left:6px">msf &gt; {_escape(msf_mod)}</span>'
        ) if msf_mod else ""
        cvss_badge = (
            f'<span class="mini-badge" style="color:{C["cyan"]};background:{C["cyan"]}22;'
            f'border-color:{C["cyan"]}44;margin-left:6px">CVSS {f.cvss}</span>'
        ) if f.cvss else ""

        cve_matches = re.findall(r'CVE-\d{4}-\d+', (f.title or "") + " " + (f.evidence or ""))
        cve_badges = "".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" rel="noopener" '
            f'class="mini-badge" style="color:{C["medium"]};background:{C["medium"]}22;'
            f'border-color:{C["medium"]}44;margin-left:4px;text-decoration:none">{cve}</a>'
            for cve in dict.fromkeys(cve_matches)
        )

        mitre = (
            f'<span class="mono muted" style="font-size:10px">{_escape(f.mitre_technique)}</span>'
        ) if f.mitre_technique else ""
        evidence_block = (
            f'<div class="fc-evidence" style="border-left-color:{color}44">'
            f'<span class="fc-evidence-lbl">$ evidence &gt;&gt; </span>{_escape(f.evidence)}</div>'
        ) if f.evidence else ""
        rem_block = (
            '<div class="fc-remediation">'
            f'<span class="fc-remediation-lbl">REMEDIATION &gt;&gt; </span>{_escape(f.remediation)}</div>'
        ) if f.remediation else ""

        search_blob = _escape(f"{f.title} {f.description} {f.evidence} {f.phase}".lower())
        card_id = f"fc{i}"
        parts.append(
            f'<div class="finding-card" data-severity="{f.severity.value}" '
            f'data-phase="{_escape(f.phase)}" data-search="{search_blob}" '
            f'style="border-left-color:{color};box-shadow:{_glow(color,4)}">'
            f'<div class="finding-header" onclick="toggleCard(\'{card_id}\')">'
            f'<span class="fc-num">#{i:02d}</span>'
            f'{_sev_badge(f.severity.value)}'
            f'<span class="fc-title">{_escape(f.title)}</span>'
            f'{cvss_badge}{cve_badges}{msf_badge}'
            f'<span id="arr_{card_id}" class="fc-arrow">▼</span>'
            '</div>'
            f'<div id="{card_id}" class="fc-body">'
            f'<p class="fc-desc">{_escape(f.description)}</p>'
            f'{evidence_block}{rem_block}'
            f'<div class="fc-meta">phase:{_escape(f.phase)} &nbsp;|&nbsp; {mitre} &nbsp;|&nbsp; {f.timestamp[:19]}</div>'
            '</div></div>'
        )
    return "".join(parts)


def _findings_toolbar(counts: dict, total: int) -> str:
    tabs = [f'<button class="sev-tab active" data-filter="all">All <span class="tab-count">{total}</span></button>']
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        tabs.append(
            f'<button class="sev-tab" data-filter="{sev}">{sev.capitalize()} <span class="tab-count">{n}</span></button>'
        )
    return (
        '<div class="toolbar">'
        '<input type="text" id="findingSearch" class="search-input" '
        'placeholder="Search findings by title, evidence, phase…" oninput="filterFindings()">'
        f'<div class="sev-tabs" id="sevTabs">{"".join(tabs)}</div>'
        '<div class="toolbar-actions">'
        '<button class="ghost-btn" onclick="setAllCards(true)">Expand all</button>'
        '<button class="ghost-btn" onclick="setAllCards(false)">Collapse all</button>'
        '</div></div>'
        '<div id="findingsEmpty" class="findings-empty" style="display:none">No findings match your filters.</div>'
    )


# ── Style & script (plain strings — never parsed as f-strings, so their
# curly braces are never a concern) ─────────────────────────────────────────

CSS_BLOCK = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:#0a0e1a;color:#e6edf3;line-height:1.6;min-height:100vh;
}
.mono{font-family:monospace}
.muted{color:#8b949e}

/* ── Scroll progress ── */
.scroll-progress{position:fixed;top:0;left:0;height:3px;width:0%;z-index:1000;
  background:linear-gradient(90deg,#00ff88,#0ea5e9);transition:width .12s ease}

/* ── Topbar (mobile) ── */
.topbar{display:none;position:sticky;top:0;z-index:800;align-items:center;gap:12px;
  padding:12px 16px;background:#080b14ee;border-bottom:1px solid #1e2d40}
.hamburger{background:none;border:1px solid #1e2d40;color:#e6edf3;font-size:16px;
  border-radius:6px;padding:4px 10px;cursor:pointer}
.hamburger:hover{border-color:#263a52}
.topbar-title{font-family:monospace;font-weight:700;letter-spacing:2px;flex:1}

/* ── Sidebar ── */
.sidebar{position:fixed;top:0;left:0;bottom:0;width:268px;background:#080b14;
  border-right:1px solid #1e2d40;overflow-y:auto;padding:22px 16px 20px;z-index:900;
  display:flex;flex-direction:column;gap:18px}
.sidebar::-webkit-scrollbar{width:6px}
.sidebar::-webkit-scrollbar-thumb{background:#263a52;border-radius:3px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:#000000aa;z-index:850}
.sidebar-overlay.show{display:block}

.brand{display:flex;align-items:center;gap:10px;padding-bottom:16px;border-bottom:1px solid #1e2d40}
.brand-mark{font-size:26px;filter:drop-shadow(0 0 6px #00ff8888)}
.brand-name{font-family:monospace;font-weight:700;font-size:15px;letter-spacing:2px;color:#e6edf3}
.brand-version{font-family:monospace;font-size:10px;color:#8b949e}

.sidebar-target{background:#0d1117;border:1px solid #1e2d40;border-radius:8px;padding:12px 14px}
.sidebar-target-label{font-family:monospace;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#8b949e}
.sidebar-target-value{font-family:monospace;font-size:13px;color:#0ea5e9;word-break:break-all;margin-top:3px}
.sidebar-target-meta{font-size:10px;color:#3d4f61;margin-top:6px;font-family:monospace}

.sidebar-nav{display:flex;flex-direction:column;gap:2px;flex:1}
.nav-link{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:6px;
  color:#8b949e;text-decoration:none;font-size:12.5px;transition:background .15s,color .15s}
.nav-link:hover{background:#0f1923;color:#e6edf3}
.nav-link.active{background:#00ff8814;color:#00ff88;box-shadow:inset 2px 0 0 #00ff88}
.nav-icon{font-size:14px;width:18px;text-align:center}
.nav-label{flex:1}
.nav-count{font-family:monospace;font-size:10px;color:#3d4f61;background:#0f1923;
  border:1px solid #1e2d40;border-radius:8px;padding:0 6px}
.nav-link.active .nav-count{color:#00ff88;border-color:#00ff8844}

.sidebar-footer{border-top:1px solid #1e2d40;padding-top:14px}
.risk-chip{text-align:center;font-family:monospace;font-weight:700;font-size:11px;
  letter-spacing:1.5px;padding:8px;border-radius:6px}

/* ── Main ── */
.main{margin-left:268px;padding:36px 40px 40px;max-width:1180px}

/* ── Panels ── */
.panel{background:#0d1117;border:1px solid #1e2d40;border-radius:12px;padding:26px 28px;margin-bottom:26px}
.panel-head{margin-bottom:6px}
.panel-title{font-size:14px;font-weight:700;font-family:monospace;text-transform:uppercase;
  letter-spacing:2px;color:#0ea5e9;border-bottom:1px solid #1e2d40;padding-bottom:12px;
  display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.panel-icon{font-size:15px}
.panel-sub{font-size:12px;color:#8b949e;font-family:monospace;margin:12px 0 14px}
.count-badge{display:inline-block;font-size:10px;padding:1px 7px;border-radius:10px;
  background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;margin-left:4px;
  font-family:monospace;vertical-align:middle}

/* ── Hero / overview ── */
.hero-panel{position:relative;overflow:hidden;
  background:linear-gradient(135deg,#0a0e1a 0%,#0d1525 55%,#0a1628 100%)}
.hero-panel::before{content:'';position:absolute;inset:0;
  background-image:radial-gradient(circle,#00ff8814 1px,transparent 1px);
  background-size:26px 26px;pointer-events:none}
.hero-panel::after{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,#00ff8866,transparent);
  animation:scanline 4s ease-in-out infinite}
@keyframes scanline{0%,100%{top:0;opacity:0}10%{opacity:1}90%{opacity:1}100%{top:100%;opacity:0}}

.hero-top{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:28px;
  align-items:flex-start;justify-content:space-between}
.hero-info{flex:2;min-width:260px}
.hero-label{font-family:monospace;font-size:10px;letter-spacing:3px;text-transform:uppercase;
  color:#8b949e;margin-bottom:8px}
.hero-title{font-size:27px;font-weight:700;display:flex;align-items:center;gap:10px}
.hero-title::before{content:'>';color:#00ff88;font-family:monospace;font-size:29px;
  animation:blink 1.2s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.hero-target{font-family:monospace;font-size:18px;color:#0ea5e9;margin:6px 0;word-break:break-all}
.hero-meta{font-size:12px;color:#8b949e;font-family:monospace;display:flex;gap:16px;
  flex-wrap:wrap;margin-top:4px}
.sev-callout{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.sev-chip{font-family:monospace;font-size:12.5px;font-weight:700;padding:6px 14px;
  border-radius:5px;border:1px solid}

.hero-risk{flex:0 0 auto}
.risk-badge{text-align:center;background:#0d1117cc;border:1px solid;border-radius:10px;
  padding:18px 26px;min-width:130px}
.risk-level{font-family:monospace;font-size:25px;font-weight:700;letter-spacing:2px}
.risk-label{font-size:10px;color:#8b949e;letter-spacing:2px;text-transform:uppercase}
.risk-sub{font-family:monospace;font-size:11px;color:#8b949e;margin-top:6px}

.hero-chart{flex:0 0 auto;display:flex;align-items:center;gap:18px}
.ring-wrap{position:relative;width:132px;height:132px}
.ring-wrap svg{display:block}
.ring-center{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center}
.ring-num{font-family:monospace;font-size:26px;font-weight:700}
.ring-lbl{font-size:9px;color:#8b949e;letter-spacing:1px}
.ring-legend{display:flex;flex-direction:column;gap:6px;font-family:monospace;font-size:12px}
.legend-item{display:flex;align-items:center;gap:8px;color:#8b949e}
.legend-dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.legend-item b{color:#e6edf3;margin-left:2px}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px;margin:26px 0 0;position:relative;z-index:1}
.stat-card{background:#0f1923aa;border:1px solid #1e2d40;border-radius:8px;
  padding:16px 18px;transition:border-color .2s,box-shadow .2s}
.stat-card:hover{border-color:#00ff8844;box-shadow:0 0 12px #00ff8822}
.stat-num{font-family:monospace;font-size:30px;font-weight:700}
.stat-lbl{font-size:10.5px;color:#8b949e;font-family:monospace;text-transform:uppercase;
  letter-spacing:1px;margin-top:2px}

.dist-card{position:relative;z-index:1;background:#0f192388;border:1px solid #1e2d40;
  border-radius:8px;padding:18px 22px;margin-top:18px}
.dist-title{font-family:monospace;font-size:10.5px;color:#8b949e;text-transform:uppercase;
  letter-spacing:2px;margin-bottom:14px}
.bar-row{margin:9px 0}
.bar-row-head{display:flex;justify-content:space-between;margin-bottom:5px}
.bar-row-label{font-family:monospace;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:1px}
.bar-row-count{font-family:monospace;font-size:11.5px;color:#8b949e}
.bar-track{background:#1e2d40;border-radius:2px;height:4px;overflow:hidden}
.bar-fill{height:4px;border-radius:2px;width:0;animation:growBar 1s ease forwards}
@keyframes growBar{from{width:0}to{width:var(--w,0%)}}

/* ── Executive summary ── */
.exec-lead{font-size:14px;color:#8b949e;line-height:1.7;margin-bottom:10px}
.exec-lead b{color:#e6edf3}
.exec-list{list-style:none;display:flex;flex-direction:column;gap:8px}
.exec-list li{font-size:13px;color:#8b949e;padding:8px 14px;background:#0f1923;
  border-left:3px solid #0ea5e9;border-radius:0 5px 5px 0}

.ai-box{background:#0f1923;border:1px solid #1e2d40;border-left:3px solid #0ea5e9;
  border-radius:0 6px 6px 0;padding:20px 24px;font-size:14px;line-height:1.8;color:#8b949e}

/* ── Tables / chips / badges ── */
.table-wrap{overflow-x:auto;margin-top:14px;border:1px solid #1e2d40;border-radius:8px}
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{text-align:left;padding:10px 14px;background:#0f1923;color:#8b949e;
  font-family:monospace;font-size:10px;text-transform:uppercase;letter-spacing:1px;
  border-bottom:1px solid #1e2d40}
.trow td{padding:10px 14px;border-bottom:1px solid #1e2d4088;vertical-align:top}
.trow:last-child td{border-bottom:none}
.trow:hover{background:#0f1923}

.badge{font-family:monospace;font-size:10px;font-weight:700;text-transform:uppercase;
  padding:3px 8px;border-radius:3px;border:1px solid;letter-spacing:1px;display:inline-block}
.mini-badge{font-family:monospace;font-size:10px;padding:2px 8px;border-radius:3px;
  border:1px solid;display:inline-block}

.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.chip{font-family:monospace;font-size:11.5px;padding:4px 10px;border-radius:4px;
  border:1px solid #1e2d40;background:#0f1923;display:inline-block}

.screenshot-item{margin:14px 0;border:1px solid #1e2d40;border-radius:8px;overflow:hidden}
.screenshot-bar{background:#0f1923;color:#8b949e;padding:8px 14px;font-size:11px;
  font-family:monospace;border-bottom:1px solid #1e2d40}
.screenshot-item img{width:100%;display:block}

/* ── Kill chain ── */
.kc-track{display:flex;align-items:center;gap:2px;overflow-x:auto;padding:6px 2px 10px;margin-top:14px}
.kc-node{display:flex;flex-direction:column;align-items:center;gap:3px;border:1px solid;
  border-radius:6px;padding:9px 13px;min-width:84px;text-align:center;flex:0 0 auto}
.kc-label{font-family:monospace;font-size:11px;font-weight:700}
.kc-tech{font-size:9px;color:#8b949e}
.kc-arrow{color:#00ff88;font-size:16px;padding:0 3px;flex:0 0 auto}

/* ── OPSEC gauge ── */
.opsec-gauge{display:flex;align-items:center;gap:26px;margin-top:14px;flex-wrap:wrap}
.opsec-rating{font-family:monospace;font-size:21px;font-weight:700}
.opsec-rating-lbl{font-size:11px;color:#8b949e;margin-top:2px}

/* ── Findings toolbar ── */
.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:14px 0 18px}
.search-input{flex:1;min-width:220px;background:#0f1923;border:1px solid #1e2d40;
  border-radius:7px;padding:9px 14px;color:#e6edf3;font-size:13px;font-family:inherit}
.search-input:focus{outline:none;border-color:#0ea5e966;box-shadow:0 0 0 3px #0ea5e922}
.sev-tabs{display:flex;gap:6px;flex-wrap:wrap}
.sev-tab{font-family:monospace;font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.5px;padding:7px 12px;border-radius:6px;border:1px solid #1e2d40;
  background:#0f1923;color:#8b949e;cursor:pointer;transition:all .15s}
.sev-tab:hover{color:#e6edf3;border-color:#263a52}
.sev-tab.active{background:#00ff8818;color:#00ff88;border-color:#00ff8855}
.tab-count{opacity:.75;margin-left:4px}
.toolbar-actions{display:flex;gap:8px}
.ghost-btn{font-family:monospace;font-size:11px;padding:7px 12px;border-radius:6px;
  border:1px solid #1e2d40;background:transparent;color:#8b949e;cursor:pointer;transition:all .15s}
.ghost-btn:hover{color:#e6edf3;border-color:#263a52;background:#0f1923}
.findings-empty{text-align:center;padding:34px;color:#3d4f61;font-family:monospace;font-size:13px}

/* ── Finding cards ── */
.sev-divider{margin:20px 0 10px;padding:7px 14px;border-left:3px solid;border-radius:0 5px 5px 0;
  display:flex;align-items:center;gap:10px}
.sev-divider-label{font-family:monospace;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px}
.sev-divider-count{font-family:monospace;font-size:11px;color:#8b949e}

.finding-card{background:#0f192366;border:1px solid #1e2d40;border-left-width:3px;
  border-radius:0 8px 8px 0;margin:10px 0;transition:border-color .2s,box-shadow .2s}
.finding-card:hover{box-shadow:0 2px 16px #00000055}
.finding-header{display:flex;align-items:center;gap:10px;cursor:pointer;padding:15px 20px;flex-wrap:wrap}
.finding-header:hover .fc-num{color:#00ff88}
.fc-num{color:#8b949e;font-family:monospace;font-size:11px;min-width:26px;transition:color .15s}
.fc-title{flex:1;font-size:14px;font-weight:600;min-width:160px}
.fc-arrow{color:#8b949e;font-size:12px;margin-left:6px;transition:transform .25s}
.fc-body{display:none;padding:0 20px 18px}
.fc-body.open{display:block}
.fc-desc{margin:0 0 10px;color:#8b949e;font-size:13px;line-height:1.6}
.fc-evidence{background:#060a10;border:1px solid #1e2d40;border-left-width:3px;color:#00ff88;
  padding:11px 14px;border-radius:4px;font-family:monospace;font-size:12px;margin:10px 0;
  white-space:pre-wrap;word-break:break-all;line-height:1.6}
.fc-evidence-lbl{color:#8b949e;user-select:none}
.fc-remediation{background:#0f1923;border-left:3px solid #00ff88;padding:11px 14px;
  margin:10px 0;border-radius:0 4px 4px 0;font-size:13px;color:#8b949e}
.fc-remediation-lbl{color:#00ff88;font-family:monospace;font-size:11px}
.fc-meta{margin-top:10px;font-size:11px;color:#3d4f61;font-family:monospace}

/* ── AD attack chain ── */
.ad-step{border:1px solid #1e2d40;border-left:3px solid #0ea5e9;border-radius:0 8px 8px 0;
  padding:15px 18px;margin:10px 0;background:#0f192366}
.ad-step-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.ad-step-num{font-family:monospace;font-size:11px;color:#0ea5e9}
.ad-step-name{font-weight:700}
.ad-step-tech{font-family:monospace;font-size:10px;color:#8b949e;background:#0d1117;
  border:1px solid #1e2d40;padding:2px 6px;border-radius:3px}
.ad-step-reason{margin:0 0 8px;font-size:13px;color:#8b949e}
.ad-cmds{background:#060a10;border:1px solid #1e2d40;border-radius:4px;padding:11px 14px;
  font-family:monospace;font-size:12px;line-height:1.8}
.ad-cmd-line{padding:2px 0}

/* ── Notes ── */
.notes-box{background:#0f192366;border:1px solid #1e2d40;border-radius:8px;padding:16px 20px;
  max-height:260px;overflow-y:auto;margin-top:14px}
.note-line{font-size:12px;font-family:monospace;color:#8b949e;padding:3px 0;
  border-bottom:1px solid #1e2d4055}
.note-line:last-child{border-bottom:none}

/* ── Footer ── */
.footer{text-align:center;padding:36px 24px 10px}
.footer-text{font-family:monospace;font-size:11px;color:#8b949e;letter-spacing:1px}
.footer-brand{color:#00ff88;font-weight:700}
.footer-sub{font-size:10px;color:#3d4f61;margin-top:6px}

/* ── Floating buttons ── */
.fab-top,.fab-print{position:fixed;right:26px;width:44px;height:44px;border-radius:50%;
  border:1px solid #1e2d40;background:#0f1923;color:#e6edf3;font-size:17px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;box-shadow:0 4px 18px #000000aa;
  z-index:700;transition:opacity .2s,transform .2s}
.fab-top{bottom:26px;opacity:0;pointer-events:none;transform:translateY(8px)}
.fab-top.visible{opacity:1;pointer-events:auto;transform:none}
.fab-print{bottom:82px}
.fab-top:hover,.fab-print:hover{border-color:#00ff8866;color:#00ff88}

/* ── Print & PDF export ── */
@media print{
  .sidebar,.sidebar-overlay,.topbar,.toolbar,.fab-top,.fab-print,.scroll-progress{display:none !important}
  .main{margin-left:0 !important;padding:0 !important;max-width:100% !important}
  .fc-body{display:block !important}
  .finding-card,.panel{page-break-inside:avoid}
}
body.pdf-export .sidebar,body.pdf-export .sidebar-overlay,body.pdf-export .topbar,
body.pdf-export .toolbar,body.pdf-export .fab-top,body.pdf-export .fab-print,
body.pdf-export .scroll-progress{display:none !important}
body.pdf-export .main{margin-left:0 !important}
body.pdf-export *{animation:none !important;transition:none !important}

/* ── Responsive ── */
@media(max-width:960px){
  .sidebar{transform:translateX(-100%);transition:transform .25s ease}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0 !important}
  .topbar{display:flex}
}
@media(max-width:640px){
  .hero-top{flex-direction:column}
  .stat-grid{grid-template-columns:1fr 1fr}
  .panel{padding:20px 18px}
  .main{padding:20px 16px 40px}
}
"""

JS_BLOCK = """
function toggleCard(id){
  var el = document.getElementById(id);
  var arr = document.getElementById('arr_' + id);
  var isOpen = el.classList.toggle('open');
  if (arr) arr.style.transform = isOpen ? 'rotate(180deg)' : '';
}

function setAllCards(open){
  document.querySelectorAll('#findings .fc-body').forEach(function(el){
    if (open) el.classList.add('open'); else el.classList.remove('open');
  });
  document.querySelectorAll('#findings .fc-arrow').forEach(function(el){
    el.style.transform = open ? 'rotate(180deg)' : '';
  });
}

function filterFindings(){
  var input = document.getElementById('findingSearch');
  var q = input ? input.value.trim().toLowerCase() : '';
  var activeTab = document.querySelector('.sev-tab.active');
  var filter = activeTab ? activeTab.getAttribute('data-filter') : 'all';
  var cards = document.querySelectorAll('.finding-card');
  var visible = 0;
  cards.forEach(function(card){
    var sev = card.getAttribute('data-severity');
    var blob = card.getAttribute('data-search') || '';
    var show = (filter === 'all' || sev === filter) && (q === '' || blob.indexOf(q) !== -1);
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.querySelectorAll('.sev-divider').forEach(function(div){
    var anyVisible = false;
    var el = div.nextElementSibling;
    while (el && !el.classList.contains('sev-divider')) {
      if (el.classList.contains('finding-card') && el.style.display !== 'none') { anyVisible = true; break; }
      el = el.nextElementSibling;
    }
    div.style.display = anyVisible ? '' : 'none';
  });
  var empty = document.getElementById('findingsEmpty');
  if (empty) empty.style.display = visible === 0 ? 'block' : 'none';
}

(function initSevTabs(){
  var tabs = document.querySelectorAll('.sev-tab');
  tabs.forEach(function(btn){
    btn.addEventListener('click', function(){
      tabs.forEach(function(b){ b.classList.remove('active'); });
      btn.classList.add('active');
      filterFindings();
    });
  });
})();

function toggleSidebar(force){
  var sb = document.getElementById('sidebar');
  var ov = document.getElementById('sidebarOverlay');
  var open = typeof force === 'boolean' ? force : !sb.classList.contains('open');
  sb.classList.toggle('open', open);
  if (ov) ov.classList.toggle('show', open);
}

(function scrollFx(){
  var progress = document.getElementById('scrollProgress');
  var fabTop = document.getElementById('fabTop');
  var links = document.querySelectorAll('.nav-link');
  var sections = Array.prototype.slice.call(document.querySelectorAll('.panel[id]'));

  function onScroll(){
    var doc = document.documentElement;
    var max = doc.scrollHeight - doc.clientHeight;
    var pct = max > 0 ? (window.scrollY / max) * 100 : 0;
    if (progress) progress.style.width = pct + '%';
    if (fabTop) fabTop.classList.toggle('visible', window.scrollY > 400);
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  if ('IntersectionObserver' in window && sections.length){
    var observer = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if (!entry.isIntersecting) return;
        var id = entry.target.id;
        links.forEach(function(l){
          l.classList.toggle('active', l.getAttribute('data-target') === id);
        });
      });
    }, { rootMargin: '-20% 0px -70% 0px', threshold: 0 });
    sections.forEach(function(s){ observer.observe(s); });
  }
})();

document.querySelectorAll('.nav-link').forEach(function(l){
  l.addEventListener('click', function(){ toggleSidebar(false); });
});

function animateCounter(el){
  var target = parseInt(el.textContent, 10);
  if (isNaN(target) || target === 0) return;
  var start = 0, dur = 800, step = 16;
  var timer = setInterval(function(){
    start += Math.ceil(target / (dur / step));
    if (start >= target) { el.textContent = target; clearInterval(timer); return; }
    el.textContent = start;
  }, step);
}
document.querySelectorAll('.stat-num').forEach(animateCounter);

document.querySelectorAll('.bar-fill').forEach(function(bar){
  var w = bar.getAttribute('data-w');
  bar.style.setProperty('--w', w + '%');
  bar.style.width = w + '%';
});
"""


# ── Main generator ────────────────────────────────────────────────────────────

def generate_html_report(state: EngagementState, ai_analysis: dict = None) -> str:
    counts = state.finding_counts()
    total = sum(counts.values())
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label = "Penetration Test" if state.mode.value == "pentest" else "Red Team"

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(state.findings, key=lambda f: sev_order.get(f.severity.value, 5))

    risk_color = (C["critical"] if counts.get("critical", 0) > 0
                  else C["high"] if counts.get("high", 0) > 2
                  else C["medium"] if counts.get("high", 0) > 0
                  else C["low"])
    risk_label = ("CRITICAL" if counts.get("critical", 0) > 0
                  else "HIGH" if counts.get("high", 0) > 2
                  else "MEDIUM" if counts.get("high", 0) > 0
                  else "LOW")
    opsec_color = C["green"] if state.opsec_score >= 70 else C["medium"] if state.opsec_score >= 40 else C["critical"]

    crit_n, high_n = counts.get("critical", 0), counts.get("high", 0)
    sev_highlight = ""
    if crit_n or high_n:
        chips = []
        if crit_n:
            chips.append(
                f'<span class="sev-chip" style="color:{C["critical"]};background:{C["critical"]}22;'
                f'border-color:{C["critical"]}55;box-shadow:{_glow(C["critical"],8)}">⚠ {crit_n} CRITICAL</span>'
            )
        if high_n:
            chips.append(
                f'<span class="sev-chip" style="color:{C["high"]};background:{C["high"]}22;'
                f'border-color:{C["high"]}55;box-shadow:{_glow(C["high"],8)}">⚠ {high_n} HIGH</span>'
            )
        sev_highlight = f'<div class="sev-callout">{"".join(chips)}</div>'

    ring_svg = _ring_chart([(counts.get(s, 0), SEV_COLOR[s]) for s in SEV_ORDER])
    legend_parts = [
        f'<div class="legend-item"><span class="legend-dot" style="background:{SEV_COLOR[s]}"></span>'
        f'{s.capitalize()} <b>{counts.get(s,0)}</b></div>'
        for s in SEV_ORDER if counts.get(s, 0)
    ]
    legend_html = "".join(legend_parts) or '<div class="legend-item muted">No findings recorded</div>'

    stat_cards = "".join(
        f'<div class="stat-card" style="border-top:2px solid {SEV_COLOR.get(s, C["cyan"])}">'
        f'<div class="stat-num" style="color:{SEV_COLOR.get(s, C["cyan"])}">{counts.get(s,0)}</div>'
        f'<div class="stat-lbl">{s.capitalize()}</div></div>'
        for s in SEV_ORDER
    ) + (
        f'<div class="stat-card" style="border-top:2px solid {C["cyan"]}">'
        f'<div class="stat-num" style="color:{C["cyan"]}">{state.cve_data.get("total",0)}</div>'
        '<div class="stat-lbl">CVEs</div></div>'
    )
    dist_bars = "".join(_bar_row(s.capitalize(), counts.get(s, 0), SEV_COLOR[s], total) for s in SEV_ORDER)

    exec_html = _executive_summary(state, counts, total, risk_label, risk_color,
                                    state.cve_data.get("total", 0), mode_label)

    ai_inner = ""
    ai_meta = ""
    if ai_analysis and "analysis" in ai_analysis:
        ai_text = _escape(ai_analysis["analysis"]).replace("\n", "<br>")
        ai_inner = f'<div class="ai-box">{ai_text}</div>'
        ai_meta = (
            '<span class="mono muted" style="font-size:11px;font-weight:400;margin-left:8px">'
            f'{_escape(str(ai_analysis.get("model","claude")))} · {ai_analysis.get("tokens_used","?")} tokens</span>'
        )

    screenshots = state.recon_data.get("screenshots", {})
    screenshot_inner = _screenshot_section(screenshots)
    shot_ok_count = sum(1 for s in screenshots.values() if not s.get("error"))

    real_ips = state.recon_data.get("real_ips", [])
    real_ip_inner = _real_ip_section(real_ips)
    confirmed_count = sum(1 for e in real_ips if e.get("confidence") == "confirmed")
    real_ip_extra = (
        f'<span class="count-badge" style="background:{C["green"]}22;color:{C["green"]};border-color:{C["green"]}44">'
        f'{confirmed_count} confirmed</span>'
    ) if confirmed_count else ""

    technologies = state.recon_data.get("technologies", [])
    tech_inner = _technologies_section(technologies)

    emails = state.recon_data.get("emails", [])
    emails_inner = _emails_section(emails)

    sub_found = state.recon_data.get("subdomains", {}).get("found", [])
    subdomain_inner = _subdomain_section(sub_found)

    open_ports = state.recon_data.get("open_ports", {})
    ports_inner = _ports_section(open_ports)

    creds_inner = _creds_section(state.default_creds_data)

    cves = state.cve_data.get("cves", [])
    cve_inner = _cve_table_section(state.cve_data)

    dirbrute_inner = _dirbrute_section(state.dirbrute_data)

    msf_modules = state.msf_data.get("modules", {})
    msf_inner = _msf_section(state.msf_data)

    ad_inner = _ad_section(state.ad_data)

    opsec_inner = _opsec_timeline_section(state.opsec_tracker_data, state.mode.value)

    kill_chain_inner = _kill_chain_section(state)

    findings_toolbar = _findings_toolbar(counts, total)
    findings_cards = _finding_cards(sorted_findings)
    findings_inner = (
        sev_highlight + findings_toolbar + findings_cards
        if findings_cards else
        sev_highlight + '<div class="findings-empty">No findings recorded during this engagement.</div>'
    )

    notes_inner = _notes_section(state.notes)

    # ── Sidebar nav ──
    nav_items = [("overview", "Overview", None), ("executive-summary", "Executive Summary", None)]
    if ai_inner:
        nav_items.append(("ai-summary", "AI Analysis", None))
    nav_items.append(("kill-chain", "Kill Chain", None))
    if screenshot_inner:
        nav_items.append(("screenshots", "Screenshots", shot_ok_count))
    if real_ip_inner:
        nav_items.append(("real-ip", "Real IP Discovery", len(real_ips)))
    if tech_inner:
        nav_items.append(("technologies", "Technologies", len(technologies)))
    if emails_inner:
        nav_items.append(("emails", "Harvested Emails", len(emails)))
    if subdomain_inner:
        nav_items.append(("subdomains", "Subdomains", len(sub_found)))
    if ports_inner:
        nav_items.append(("ports", "Open Ports", len(open_ports)))
    if creds_inner:
        nav_items.append(("credentials", "Default Credentials", len(state.default_creds_data.get("vulnerable", []))))
    if cve_inner:
        nav_items.append(("cve", "CVE Findings", len(cves)))
    if dirbrute_inner:
        nav_items.append(("dirbrute", "Directory Brute-Force", state.dirbrute_data.get("total", 0)))
    if msf_inner:
        nav_items.append(("msf", "Metasploit Modules", len(msf_modules)))
    nav_items.append(("findings", "Findings", total))
    if ad_inner:
        nav_items.append(("ad-chain", "AD Attack Chain", None))
    if opsec_inner:
        nav_items.append(("opsec", "OPSEC Timeline", None))
    nav_items.append(("notes", "Engagement Log", len(state.notes)))

    nav_html = "".join(
        f'<a href="#{nid}" class="nav-link" data-target="{nid}">'
        f'<span class="nav-icon">{ICON.get(nid, "▶")}</span>'
        f'<span class="nav-label">{_escape(label)}</span>'
        + (f'<span class="nav-count">{cnt}</span>' if cnt is not None else "")
        + '</a>'
        for nid, label, cnt in nav_items
    )

    # ── Panels, in body order ──
    panels = []

    overview_inner = (
        '<div class="hero-top"><div class="hero-info">'
        '<div class="hero-label">GHOSTRECON v2.0.0 :: THREAT INTELLIGENCE REPORT</div>'
        f'<h1 class="hero-title">{_escape(mode_label)}</h1>'
        f'<div class="hero-target">{_escape(state.target)}</div>'
        '<div class="hero-meta">'
        f'<span>⏱ {state.elapsed()}</span>'
        f'<span>🗓 {generated_at}</span>'
        f'<span>📈 OPSEC <b style="color:{opsec_color}">{state.opsec_score}/100</b></span>'
        f'</div>{sev_highlight}</div>'
        '<div class="hero-risk">'
        f'<div class="risk-badge" style="border-color:{risk_color}55;box-shadow:{_glow(risk_color,12)}">'
        '<div class="risk-label">Risk Level</div>'
        f'<div class="risk-level" style="color:{risk_color};text-shadow:{_glow(risk_color,8)}">{risk_label}</div>'
        f'<div class="risk-sub">{total} finding{"s" if total != 1 else ""}</div>'
        '</div></div>'
        '<div class="hero-chart">'
        f'<div class="ring-wrap">{ring_svg}<div class="ring-center">'
        f'<div class="ring-num">{total}</div><div class="ring-lbl">FINDINGS</div></div></div>'
        f'<div class="ring-legend">{legend_html}</div>'
        '</div></div>'
        f'<div class="stat-grid">{stat_cards}</div>'
        f'<div class="dist-card"><div class="dist-title">Finding Distribution</div>{dist_bars}</div>'
    )
    panels.append(f'<section class="panel hero-panel" id="overview">{overview_inner}</section>')

    panels.append(_panel("executive-summary", "Executive Summary", exec_html))

    if ai_inner:
        panels.append(_panel("ai-summary", "AI Executive Summary", ai_inner, extra=ai_meta))

    panels.append(_panel("kill-chain", "Kill Chain", kill_chain_inner))

    if screenshot_inner:
        panels.append(_panel("screenshots", "Screenshots", screenshot_inner, count=shot_ok_count))
    if real_ip_inner:
        panels.append(_panel("real-ip", "Real IP Discovery", real_ip_inner, count=len(real_ips),
                              subtitle="Potential origin IPs discovered behind CDN / WAF layer.",
                              extra=real_ip_extra))
    if tech_inner:
        panels.append(_panel(
            "technologies", "Detected Technologies", tech_inner, count=len(technologies),
            subtitle="CMS, frameworks, libraries and server-side stack identified via headers, "
                     "body analysis and path probing."
        ))
    if emails_inner:
        panels.append(_panel(
            "emails", "Harvested Emails", emails_inner, count=len(emails),
            subtitle="Email addresses discovered from homepage, /contact, /about, /robots.txt."
        ))
    if subdomain_inner:
        panels.append(_panel("subdomains", "Subdomains", subdomain_inner, count=len(sub_found)))
    if ports_inner:
        panels.append(_panel("ports", "Open Ports", ports_inner, count=len(open_ports)))
    if creds_inner:
        panels.append(_panel("credentials", "Default Credentials Found", creds_inner, title_color=C["critical"]))
    if cve_inner:
        panels.append(_panel("cve", "CVE Findings", cve_inner, count=len(cves)))
    if dirbrute_inner:
        panels.append(_panel("dirbrute", "Directory Brute-Force", dirbrute_inner,
                              count=state.dirbrute_data.get("total", 0)))
    if msf_inner:
        panels.append(_panel("msf", "Metasploit Modules", msf_inner, count=len(msf_modules)))

    panels.append(_panel("findings", "Findings", findings_inner, count=total))

    if ad_inner:
        panels.append(_panel("ad-chain", "AD Attack Chain", ad_inner))
    if opsec_inner:
        panels.append(_panel("opsec", "OPSEC Timeline", opsec_inner))

    panels.append(_panel("notes", "Engagement Log", notes_inner))

    body_html = "".join(panels)

    doc = []
    doc.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
    doc.append('<meta charset="UTF-8">\n')
    doc.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">\n')
    doc.append('<meta name="color-scheme" content="dark">\n')
    doc.append(f'<title>GHOSTRECON :: {_escape(state.target)}</title>\n')
    doc.append("<style>")
    doc.append(CSS_BLOCK)
    doc.append("</style>\n</head>\n<body>\n")
    doc.append('<div class="scroll-progress" id="scrollProgress"></div>\n')
    doc.append(
        '<div class="topbar">'
        '<button class="hamburger" onclick="toggleSidebar()" aria-label="Toggle navigation">☰</button>'
        '<div class="topbar-title">GHOSTRECON</div>'
        '<button class="hamburger" onclick="window.print()" aria-label="Print report">🖨</button>'
        '</div>\n'
    )
    doc.append(
        '<aside class="sidebar" id="sidebar">'
        '<div class="brand"><div class="brand-mark">👻</div>'
        '<div><div class="brand-name">GHOSTRECON</div><div class="brand-version">v2.0.0</div></div></div>'
        '<div class="sidebar-target">'
        '<div class="sidebar-target-label">Target</div>'
        f'<div class="sidebar-target-value">{_escape(state.target)}</div>'
        f'<div class="sidebar-target-meta">{_escape(mode_label)} · {generated_at}</div>'
        '</div>'
        f'<nav class="sidebar-nav">{nav_html}</nav>'
        '<div class="sidebar-footer">'
        f'<div class="risk-chip" style="background:{risk_color}18;color:{risk_color};'
        f'border:1px solid {risk_color}55">{risk_label} RISK</div>'
        '</div></aside>\n'
        '<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar(false)"></div>\n'
    )
    doc.append(f'<main class="main" id="mainContent">{body_html}')
    doc.append(
        '<footer class="footer">'
        '<div class="footer-text"><span class="footer-brand">GHOSTRECON v2.0.0</span> by the GhostRecon Project'
        f'&nbsp;·&nbsp;{generated_at}&nbsp;·&nbsp;<span class="muted">For authorized security testing only</span></div>'
        '<div class="footer-sub">This report may contain sensitive information. Handle and distribute accordingly.</div>'
        '</footer></main>\n'
    )
    doc.append('<button class="fab-print" onclick="window.print()" title="Print / Save as PDF">🖨</button>\n')
    doc.append(
        '<button class="fab-top" id="fabTop" '
        "onclick=\"window.scrollTo({top:0,behavior:'smooth'})\" title=\"Back to top\">↑</button>\n"
    )
    doc.append("<script>")
    doc.append(JS_BLOCK)
    doc.append("</script>\n</body>\n</html>")

    return "".join(doc)


def save_report(state: EngagementState, ai_analysis: dict = None,
                output_dir: str = ".") -> dict:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{state.target.replace('.','_').replace('/','_').replace(':','_')}_{timestamp}"

    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    html_path = os.path.join(output_dir, f"{base_name}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(state, ai_analysis))
    paths["html"] = html_path

    json_path = os.path.join(output_dir, f"{base_name}.json")
    export = {
        "target":          state.target,
        "mode":            state.mode.value,
        "generated_at":    datetime.now().isoformat(),
        "elapsed":         state.elapsed(),
        "findings":        [f.to_dict() for f in state.findings],
        "finding_counts":  state.finding_counts(),
        "recon_summary": {
            "open_ports":       list(state.recon_data.get("open_ports", {}).keys()),
            "web_ports":        list(state.recon_data.get("web", {}).keys()),
            "subdomains_found": len(state.recon_data.get("subdomains", {}).get("found", [])),
        },
        "technologies":  state.recon_data.get("technologies", []),
        "emails":        state.recon_data.get("emails", []),
        "ad_detected":   state.ad_data.get("ad_detected", False),
        "cve_total":     state.cve_data.get("total", 0),
        "opsec_score":   state.opsec_score,
        "opsec_rating":  state.opsec_tracker_data.get("rating", "N/A"),
        "msf_modules":   state.msf_data.get("total", 0),
        "notes":         state.notes,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)
    paths["json"] = json_path

    return paths


# ── Plugin registration ───────────────────────────────────────────────────────
# Report generation is modeled as a plugin too (rather than a bespoke step
# bolted onto the end of main.py) so it participates in the same dependency
# graph as everything else: it simply depends on every other plugin that
# might have run, and the pipeline's dependency resolver ignores any of
# those that were disabled for this engagement.

from core.plugin import Plugin, PluginResult  # noqa: E402
from core.orchestrator import Phase  # noqa: E402
from core.registry import register  # noqa: E402


@register
class ReportPlugin(Plugin):
    name = "report"
    display_name = "Report Generation"
    phase = Phase.REPORT
    depends_on = [
        "recon", "subdomain", "web", "jwt_analyzer", "fingerprint",
        "default_creds", "dirbrute", "waf_bypass", "shodan_recon",
        "cve", "msf_bridge", "screenshot", "opsec", "ai_engine",
    ]
    icon = "◆"

    def enabled(self, ctx) -> bool:
        return not ctx.flag("no_report")

    async def run(self, ctx) -> PluginResult:
        # Collapse findings that different plugins raised for the same
        # underlying issue under slightly different titles.
        ctx.state.dedupe_findings()

        output_dir = ctx.flags.get("output_dir", "./reports")
        os.makedirs(output_dir, exist_ok=True)
        ai_result = getattr(ctx.state, "ai_result", None)
        paths = save_report(ctx.state, ai_result if ai_result else None, output_dir)

        summary = [f"HTML report: {paths['html']}", f"JSON export: {paths['json']}"]

        if ctx.flag("pdf"):
            from output.pdf_export import export_pdf
            pdf_path = await export_pdf(paths["html"], output_dir, ctx.state.target, ctx.console)
            if pdf_path:
                paths["pdf"] = pdf_path
                summary.append(f"PDF export: {pdf_path}")

        return PluginResult(data=paths, summary=summary)
