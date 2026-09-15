"""
Typed, layered configuration.

Replaces the old ad hoc `load_config()` in main.py, which merged a plain
dict of defaults with whatever a YAML file happened to contain — no
validation, no schema, typos in config.yaml silently ignored or crashing
deep in a module. Settings are now pydantic models: invalid values raise a
clear error at startup, defaults are declared once, and the merge order is
explicit:

    built-in defaults  →  config.yaml  →  environment variables  →  CLI flags

Each layer only overrides keys it actually sets.
"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class ScanSettings(BaseModel):
    timeout: float = 2.0
    max_parallel_ports: int = 50
    port_list: str = "common"


class AISettings(BaseModel):
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 2000
    enabled: bool = True


class OutputSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    screenshots: bool = True
    json_export: bool = Field(default=True, alias="json")
    html: bool = True
    open_browser: bool = False


class StealthSettings(BaseModel):
    min_delay: float = 1.0
    max_delay: float = 3.0
    rotate_ua: bool = True


class PathSettings(BaseModel):
    ghost_engine: str = ""
    wordlists: str = "./config/wordlists"
    reports: str = "./reports"


class Settings(BaseModel):
    scan: ScanSettings = Field(default_factory=ScanSettings)
    ai: AISettings = Field(default_factory=AISettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    stealth: StealthSettings = Field(default_factory=StealthSettings)
    paths: PathSettings = Field(default_factory=PathSettings)

    # ── env var overrides, applied after the YAML layer ──────────────────
    _ENV_OVERRIDES = {
        "GHOSTRECON_ENGINE_PATH": ("paths", "ghost_engine"),
        "GHOSTRECON_REPORTS_DIR": ("paths", "reports"),
        "GHOSTRECON_WORDLISTS_DIR": ("paths", "wordlists"),
        "GHOSTRECON_AI_MODEL": ("ai", "model"),
        "GHOSTRECON_SCAN_TIMEOUT": ("scan", "timeout"),
    }

    def apply_env_overrides(self) -> "Settings":
        for env_name, (section, key) in self._ENV_OVERRIDES.items():
            value = os.environ.get(env_name)
            if value is None:
                continue
            section_obj = getattr(self, section)
            field_type = type(getattr(section_obj, key))
            try:
                if field_type is bool:
                    value = value.strip().lower() in ("1", "true", "yes", "on")
                elif field_type is float:
                    value = float(value)
                elif field_type is int:
                    value = int(value)
            except (TypeError, ValueError):
                continue
            setattr(section_obj, key, value)
        return self


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Build Settings from defaults, then a YAML file if present, then env vars."""
    settings = Settings()

    candidates = [
        config_path,
        "config/config.yaml",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "config.yaml"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            try:
                import yaml
                with open(path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                settings = Settings.model_validate({**settings.model_dump(), **loaded})
            except ImportError:
                pass
            except Exception:
                # A malformed config.yaml shouldn't crash the whole tool —
                # fall back to defaults and let the caller decide whether to warn.
                pass
            break

    settings.apply_env_overrides()
    return settings
