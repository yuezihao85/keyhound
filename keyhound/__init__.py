"""keyhound — a zero-dependency secret scanner for git repos and CI."""

__version__ = "0.1.0"
__all__ = ["__version__", "Scanner", "Config", "RuleSet", "ScanResult", "Finding"]

from .config import Config, load_config, write_template
from .rules import BUILTIN_RULES, Rule, RuleSet, rule_from_dict
from .scanner import Finding, ScanResult, Scanner, mask_secret, fingerprint
from .baseline import load as load_baseline, dump as dump_baseline
