"""Command line interface for keyhound.

Exit codes
----------
0  no active findings (or baseline/init command succeeded)
1  active findings at or above --fail-on
2  bad arguments, unreadable config/baseline, or I/O failure
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .baseline import DEFAULT_BASELINE, dump as dump_baseline, load as load_baseline
from .config import CONFIG_FILENAME, load_config, write_template
from .reporters import render
from .rules import BUILTIN_RULES, SEVERITY_ORDER, RuleSet
from .scanner import Scanner

SEVERITIES = ("low", "medium", "high", "critical")
FORMATS = ("console", "json", "sarif")

DESCRIPTION = """\
keyhound — zero-dependency secret scanner for repos, pre-commit and CI.

Examples:
  keyhound .                          scan the current tree
  keyhound --format sarif --output out.sarif .
  keyhound --init                     write a default .keyhound.json
  keyhound --init-baseline .          accept current findings as known
  git diff --cached | keyhound -      scan staged diff from stdin
  keyhound --list-rules               show every built-in detector
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyhound",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Docs: https://github.com/yuezihao85/keyhound",
    )
    parser.add_argument("paths", nargs="*", default=None,
                        help="files or directories to scan (default: .); '-' = stdin")
    parser.add_argument("-V", "--version", action="version",
                        version="keyhound %s" % __version__)
    parser.add_argument("-c", "--config", metavar="FILE",
                        help="config file (default: auto-discover .keyhound.json)")
    parser.add_argument("--no-config", action="store_true",
                        help="ignore any discovered config file")

    output = parser.add_argument_group("output")
    output.add_argument("-f", "--format", choices=FORMATS, default="console",
                        help="report format (default: console)")
    output.add_argument("-o", "--output", metavar="FILE",
                        help="write report to FILE instead of stdout")
    output.add_argument("--color", choices=("auto", "always", "never"),
                        default="auto", help="console color mode")
    output.add_argument("--show-suppressed", action="store_true",
                        help="also list baseline-suppressed findings")

    policy = parser.add_argument_group("policy")
    policy.add_argument("--fail-on", choices=SEVERITIES, default=None,
                        help="minimum severity that sets exit code 1 (default: low)")
    policy.add_argument("--min-severity", choices=SEVERITIES, default="low",
                        help="hide findings below this level (default: low)")
    policy.add_argument("--baseline", metavar="FILE", default=None,
                        help="baseline file (default: .keyhound-baseline.json if present)")
    policy.add_argument("--no-baseline", action="store_true",
                        help="do not apply any baseline")
    policy.add_argument("--init-baseline", action="store_true",
                        help="record current findings as the baseline, then exit 0")
    policy.add_argument("--update-baseline", action="store_true",
                        help="add current findings to an existing baseline, then exit 0")
    policy.add_argument("--reason", default="",
                        help="reason stored with new baseline entries")

    filters = parser.add_argument_group("filters")
    filters.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                         help="extra ignore pattern (repeatable)")
    filters.add_argument("--include", action="append", default=[], metavar="GLOB",
                         help="only scan matching paths (repeatable)")
    filters.add_argument("--disable-rule", action="append", default=[], metavar="ID",
                         help="disable a rule by id (repeatable)")
    filters.add_argument("--no-gitignore", action="store_true",
                         help="ignore .gitignore contents")
    filters.add_argument("--max-size", type=int, default=None, metavar="BYTES",
                         help="skip files larger than BYTES")
    filters.add_argument("--min-entropy", type=float, default=None, metavar="BITS",
                         help="entropy threshold for heuristic rules (default: 3.5)")
    filters.add_argument("--min-length", type=int, default=None, metavar="N",
                         help="minimum secret length (default: 16)")

    misc = parser.add_argument_group("setup")
    misc.add_argument("--init", action="store_true",
                      help="write a default .keyhound.json and exit")
    misc.add_argument("--list-rules", action="store_true",
                      help="print the built-in rule catalog and exit")
    return parser


def _write(text: str, destination: Optional[str]) -> bool:
    """Write UTF-8 safely; returns False on failure."""
    try:
        if destination:
            directory = os.path.dirname(os.path.abspath(destination))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(destination, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        else:
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except UnicodeEncodeError:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                    sys.stdout.write(text)
                    sys.stdout.flush()
                else:
                    sys.stdout.write(text.encode("utf-8", "replace")
                                     .decode("ascii", "replace"))
                    sys.stdout.flush()
        return True
    except OSError as exc:
        sys.stderr.write("keyhound: output error: %s\n" % exc)
        return False


def _list_rules(rule_set: RuleSet) -> str:
    lines = ["%-30s %-9s %s" % ("RULE ID", "SEVERITY", "DESCRIPTION"),
             "-" * 88]
    for rule in sorted(rule_set, key=lambda r: r.id):
        lines.append("%-30s %-9s %s" % (rule.id, rule.severity, rule.description))
    lines.append("-" * 88)
    lines.append("%d rules" % len(rule_set))
    return "\n".join(lines) + "\n"


def _resolve_baseline_path(args, config) -> Optional[str]:
    if args.no_baseline:
        return None
    if args.baseline:
        return args.baseline
    default = DEFAULT_BASELINE
    if os.path.isfile(default):
        return default
    # Also look next to an explicitly discovered config file.
    if config.config_path:
        sibling = os.path.join(os.path.dirname(config.config_path), DEFAULT_BASELINE)
        if os.path.isfile(sibling):
            return sibling
    return None


def _default_paths(args) -> List[str]:
    paths = args.paths if args.paths is not None else ["."]
    return list(paths) if paths else ["."]


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init:
        target = os.path.join(os.getcwd(), CONFIG_FILENAME)
        if write_template(target):
            sys.stdout.write("created %s\n" % CONFIG_FILENAME)
        else:
            sys.stdout.write("%s already exists, left unchanged\n" % CONFIG_FILENAME)
        return 0

    try:
        config = (None if args.no_config
                  else load_config(args.config, root=os.getcwd()))
    except (IOError, ValueError) as exc:
        sys.stderr.write("keyhound: config error: %s\n" % exc)
        return 2
    if config is None:
        from .config import Config
        config = Config()
        config.build_allowlist()

    # CLI overrides win over the config file.
    if args.exclude:
        config.exclude = list(config.exclude) + list(args.exclude)
    if args.include:
        config.include = list(args.include)
    if args.disable_rule:
        config.disabled_rules = list(config.disabled_rules) + list(args.disable_rule)
    if args.no_gitignore:
        config.use_gitignore = False
    if args.max_size is not None:
        if args.max_size < 0:
            sys.stderr.write("keyhound: --max-size must be >= 0\n")
            return 2
        config.max_size_bytes = args.max_size
    if args.min_entropy is not None:
        if not (0.0 <= args.min_entropy <= 8.0):
            sys.stderr.write("keyhound: --min-entropy must be in [0, 8]\n")
            return 2
        config.min_entropy = args.min_entropy
    if args.min_length is not None:
        if args.min_length < 1:
            sys.stderr.write("keyhound: --min-length must be >= 1\n")
            return 2
        config.min_length = args.min_length

    fail_on = args.fail_on or config.fail_on
    if fail_on not in SEVERITY_ORDER:
        sys.stderr.write("keyhound: invalid fail_on %r (choose from %s)\n"
                         % (fail_on, ", ".join(SEVERITIES)))
        return 2

    try:
        rule_set = RuleSet(disabled=config.disabled_rules,
                           custom=config.custom_rules)
    except ValueError as exc:
        sys.stderr.write("keyhound: rule error: %s\n" % exc)
        return 2

    if args.list_rules:
        return 0 if _write(_list_rules(rule_set), args.output) else 2

    baseline_path = _resolve_baseline_path(args, config)
    baseline: set = set()
    if baseline_path and os.path.isfile(baseline_path):
        try:
            baseline = load_baseline(baseline_path)
        except (OSError, ValueError) as exc:
            sys.stderr.write("keyhound: baseline error: %s\n" % exc)
            return 2

    scanner = Scanner(config, rule_set, baseline=baseline,
                      severity=args.min_severity)
    paths = _default_paths(args)

    if "-" in paths:
        if len(paths) > 1:
            sys.stderr.write("keyhound: '-' (stdin) cannot be combined with paths\n")
            return 2
        try:
            text = sys.stdin.read()
        except (OSError, UnicodeError) as exc:
            sys.stderr.write("keyhound: stdin error: %s\n" % exc)
            return 2
        result = scanner.scan_text(text, label="stdin")
    else:
        result = scanner.scan(paths)

    if args.init_baseline or args.update_baseline:
        target = args.baseline or DEFAULT_BASELINE
        existing = result.suppressed
        if args.update_baseline:
            # Re-scan without suppression so full current state is captured.
            full = Scanner(config, rule_set, severity=args.min_severity).scan(paths)
            to_store = full.findings
        else:
            to_store = list(result.findings) + list(result.suppressed)
        try:
            count = dump_baseline(target, to_store, reason=args.reason)
        except OSError as exc:
            sys.stderr.write("keyhound: baseline write error: %s\n" % exc)
            return 2
        sys.stdout.write("wrote %d entr%s to %s\n"
                         % (count, "y" if count == 1 else "ies", target))
        return 0

    report = render(result, args.format, color=args.color)
    if not _write(report, args.output):
        return 2

    if result.errors and args.format == "console":
        return 2
    threshold = SEVERITY_ORDER[fail_on]
    hit = any(SEVERITY_ORDER.get(f.severity, 0) >= threshold
              for f in result.findings)
    return 1 if hit else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
