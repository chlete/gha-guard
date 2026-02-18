from .engine import run_all_rules, Finding, Severity

__all__ = ["run_all_rules", "Finding", "Severity"]

# Import all rule modules so they register themselves via @register_rule
from . import unpinned_actions
from . import permissions
from . import script_injection
from . import dangerous_triggers
from . import secret_handling
