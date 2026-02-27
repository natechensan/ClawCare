"""Guard configuration — re-exports from the unified config module.

All configuration logic now lives in ``clawcare.config``.  This module
exists solely for backward compatibility so that existing imports like::

    from clawcare.guard.config import GuardConfig, load_guard_config

continue to work without changes.
"""

# Re-export everything from the unified config module.
from clawcare.config import (  # noqa: F401
    AuditConfig,
    GuardConfig,
    load_guard_config,
    USER_CONFIG_DIR as DEFAULT_CONFIG_DIR,
    USER_CONFIG_PATH as DEFAULT_CONFIG_PATH,
    DEFAULT_LOG_PATH,
)
