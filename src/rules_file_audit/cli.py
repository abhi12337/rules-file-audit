"""Command line interface.

  rules-file-audit scan [PATH ...]
  rules-file-audit rules
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap

from . import __version__
from .findings import RULES, SEVERITIES, SEVERITY_RANK, Finding
from .report import render_json, render_text, use_color
from .scanner import MAX_BYTES_DEFAULT, ScanResult, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    lim = SEVERITY_RANK[fail_on]
    return EXIT_FINDINGS if any(SEVERITY_RANK[f.severity] <= lim for f in findings) else EXIT_OK


def _filter_min(findings: list[Finding], min_sev: str) -> list[Finding]:
    lim = SEVERITY_RANK[min_sev]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= lim]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rules-file-audit",
        description="Static audit of AI coding-assistant rules files (.cursorrules, CLAUDE.md, AGENTS.md, "
                    "copilot-instructions.md, ...) and agent permission configs for hidden or dangerous "
                    "instructions. Reads files only; no network.",
        epilog="A clean report is not a guarantee. See 'What it does not check' in the README.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan folders / files")
    s.add_argument("paths", nargs="*", default=None, help="folders or files to scan (default: .)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. --exclude 'docs/*'")
    s.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="ignore a rule id (repeatable), e.g. --disable RFA050")
    s.add_argument("--max-file-mb", type=float, default=MAX_BYTES_DEFAULT / 1024 / 1024,
                   help="skip files larger than this (default: 2)")
    s.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    s.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="hide findings below this severity (default: info = show all)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    s.add_argument("--brief", action="store_true", help="omit the why/fix text")

    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def cmd_scan(args) -> int:
    paths = args.paths or ["."]
    for p in paths:
        if not os.path.exists(p):
            print(f"error: {p} does not exist", file=sys.stderr)
            return EXIT_ERROR
    unknown = [r for r in args.disable if r.upper() not in RULES]
    if unknown:
        print(f"error: unknown rule id(s): {', '.join(unknown)} (see `rules-file-audit rules`)", file=sys.stderr)
        return EXIT_ERROR
    disabled = {r.upper() for r in args.disable}
    max_bytes = int(args.max_file_mb * 1024 * 1024)
    results: list[ScanResult] = [scan_path(p, excludes=args.exclude, max_bytes=max_bytes,
                                           check_git="RFA050" not in disabled) for p in paths]
    findings = [f for r in results for f in r.findings if f.rule_id not in disabled]
    if len(results) > 1:   # make locations unambiguous
        for r, label in zip(results, paths):
            if os.path.isfile(label):
                continue
            for f in r.findings:
                if f.file and label != ".":
                    f.file = f"{label.rstrip('/')}/{f.file}".replace("\\", "/")
    exit_code = _exit_code(findings, args.fail_on)
    shown = _filter_min(findings, args.min_severity)
    files = sum(r.files_scanned for r in results)
    instr = [c for r in results for c in r.instruction_files]
    configs = [c for r in results for c in r.config_files]
    suppressed = sum(r.suppressed for r in results)
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "targets": [r.root for r in results], "files_scanned": files, "instruction_files": instr,
            "config_files": configs, "suppressed_by_inline_ignore": suppressed, "exit_code": exit_code,
        }))
    else:
        header = [f"Scanned {', '.join(paths)}",
                  f"{files} file(s): {len(instr)} instruction file(s), {len(configs)} agent config file(s)"]
        if not files:
            header.append("No AI coding-assistant rules files or agent configs found.")
        footer = []
        if suppressed:
            footer.append(f"{suppressed} finding(s) suppressed by inline '{'rules-file-audit: ignore'}' comments "
                          f"(review them: a hostile change can add the same comment).")
        footer.append(f"Exit code: {exit_code}")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=footer))
    return exit_code


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.title}")
        print(textwrap.fill(r.why, 92, initial_indent="    ", subsequent_indent="    "))
        print("    Fix:")
        print(textwrap.indent(Finding(r.id, "low", "").fix, "      "))
        print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "rules": cmd_rules}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
