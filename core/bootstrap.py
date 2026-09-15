"""
Plugin bootstrap — importing this module triggers every plugin's
`@register` decorator, populating core.registry.registry.

Kept as a single explicit list (rather than a package-scan / glob-import)
so it's obvious which modules are part of the pipeline, and so a module
that intentionally isn't a plugin (e.g. utils/logger.py) is never
accidentally auto-discovered and imported for side effects.
"""

from modules import recon            # noqa: F401
from modules import subdomain         # noqa: F401
from modules import web               # noqa: F401
from modules import jwt_analyzer      # noqa: F401
from modules import fingerprint       # noqa: F401
from modules import default_creds     # noqa: F401
from modules import dirbrute          # noqa: F401
from modules import waf_bypass        # noqa: F401
from modules import shodan_recon      # noqa: F401
from modules import cve               # noqa: F401
from modules import msf_bridge        # noqa: F401
from modules import screenshot        # noqa: F401
from modules import opsec             # noqa: F401
from modules import ai_engine         # noqa: F401
from output import report             # noqa: F401

from core.registry import registry


def bootstrapped_registry():
    return registry
