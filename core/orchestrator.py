"""
GhostRecon — Core Engine
"""

__version__ = "2.0.0"

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Mode(str, Enum):
    PENTEST = "pentest"
    REDTEAM = "redteam"


class Phase(str, Enum):
    RECON = "recon"
    SUBDOMAIN = "subdomain"
    WEB = "web"
    AD = "ad"
    CVE = "cve"
    SCREENSHOT = "screenshot"
    AI = "ai"
    REPORT = "report"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    remediation: str = ""
    cvss: float = 0.0
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "phase": self.phase,
            "timestamp": self.timestamp,
        }


@dataclass
class EngagementState:
    target: str
    mode: Mode
    scope: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    recon_data: dict = field(default_factory=dict)
    web_data: dict = field(default_factory=dict)
    ad_data: dict = field(default_factory=dict)
    cve_data: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    opsec_score: int = 100
    opsec_tracker_data: dict = field(default_factory=dict)
    waf_bypass_data: dict = field(default_factory=dict)
    default_creds_data: dict = field(default_factory=dict)
    msf_data: dict = field(default_factory=dict)
    dirbrute_data: dict = field(default_factory=dict)
    jwt_data: dict = field(default_factory=dict)
    shodan_data: dict = field(default_factory=dict)
    current_phase: Phase = Phase.RECON
    start_time: float = field(default_factory=time.time)
    notes: list = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_note(self, note: str):
        self.notes.append(f"[{datetime.now().strftime('%H:%M:%S')}] {note}")

    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        return f"{secs // 60}m {secs % 60}s"

    def finding_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def dedupe_findings(self) -> None:
        """
        Collapse findings that different plugins raised for the same
        underlying issue under slightly different titles (e.g. recon's
        "HSTS missing" vs. web's "Missing security header:
        Strict-Transport-Security"), keeping the more specific phase's
        version and the original encounter order.
        """
        title_aliases = {
            "csp header missing": "content-security-policy",
            "csp missing": "content-security-policy",
            "missing csp header": "content-security-policy",
            "content security policy missing": "content-security-policy",
            "content-security-policy header missing": "content-security-policy",
            "hsts header missing": "strict-transport-security",
            "hsts missing": "strict-transport-security",
            "missing hsts header": "strict-transport-security",
            "http strict transport security missing": "strict-transport-security",
            "strict-transport-security header missing": "strict-transport-security",
            "x-frame-options header missing": "x-frame-options",
            "x-frame-options missing": "x-frame-options",
            "clickjacking protection missing": "x-frame-options",
            "x-content-type-options header missing": "x-content-type-options",
            "x-content-type-options missing": "x-content-type-options",
            "referrer-policy header missing": "referrer-policy",
            "referrer-policy missing": "referrer-policy",
            "permissions-policy header missing": "permissions-policy",
            "permissions-policy missing": "permissions-policy",
            "feature-policy header missing": "permissions-policy",
            "feature-policy missing": "permissions-policy",
        }
        phase_priority = {"web": 0, "recon": 1}

        def norm_title(t: str) -> str:
            s = (t or "").lower().strip()
            if s in title_aliases:
                return title_aliases[s]
            s = s.removeprefix("missing security header: ")
            s = s.removesuffix(" missing")
            return s.strip()

        best: dict = {}
        for f in self.findings:
            key = norm_title(f.title)
            if key not in best:
                best[key] = f
            else:
                curr_pri = phase_priority.get(getattr(best[key], "phase", ""), 99)
                new_pri = phase_priority.get(getattr(f, "phase", ""), 99)
                if new_pri < curr_pri:
                    best[key] = f

        seen: set = set()
        unique = []
        for f in self.findings:
            key = norm_title(f.title)
            if key not in seen:
                seen.add(key)
                unique.append(best[key])
        self.findings = unique
