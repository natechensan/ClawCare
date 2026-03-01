"""Guard configuration — re-exports from the unified config module.

All configuration logic now lives in ``clawcare.config``.  This module
exists solely for backward compatibility so that existing imports like::

    from clawcare.guard.config import GuardConfig, load_guard_config

continue to work without changes.
"""

# Re-export everything from the unified config module.
from clawcare.config import (  # noqa: F401
    DEFAULT_LOG_PATH,
    AuditConfig,
    GuardConfig,
    load_guard_config,
)
