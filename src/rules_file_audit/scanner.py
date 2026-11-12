"""Finds AI coding-assistant instruction files and agent configs and dispatches the checks.

Reads local files only. The one external program it may run is `git ls-files` (RFA050),
with core.fsmonitor disabled so a hostile repository's git config cannot run anything.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config_scan import scan_claude_settings, scan_codex_toml, scan_generic_config, scan_vscode_settings
from .findings import Finding
from .text_scan import IGNORE_MARK, scan_instructions
from .unicode_scan import scan_unicode

MAX_BYTES_DEFAULT = 2 * 1024 * 1024
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", ".venv", "venv",
             "__pycache__", "site-packages", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
             "coverage", ".turbo", ".cache", ".idea", "target", "vendor", ".gradle", "bower_components"}
AGENT_DOT_DIRS = {".cursor", ".claude", ".github", ".roo", ".continue", ".windsurf", ".clinerules", ".kiro", ".junie",
                  ".gemini", ".vscode", ".codex", ".amazonq", ".augment", ".idx", ".openhands", ".trae"}
INSTRUCTION_NAMES = {".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".continuerules", ".rules",
                     ".augment-guidelines", "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
                     "copilot-instructions.md"}
TEXT_EXT = {"", ".md", ".mdc", ".markdown", ".txt", ".prompt", ".yaml", ".yml"}
UNICODE_ONLY_RULES = ("RFA001", "RFA002", "RFA003")   # never suppressed by an inline comment
LOCAL_BY_DESIGN = {"claude.local.md", "settings.local.json"}


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    instruction_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    suppressed: int = 0


def classify(rel: str) -> str | None:
    """'instructions', 'claude', 'vscode', 'codex', 'config' or None for a repo-relative path."""
    parts = rel.replace("\\", "/").split("/")
    lp = [p.lower() for p in parts]
    name = lp[-1]
    ext = os.path.splitext(name)[1] if not name.startswith(".") or name.count(".") > 1 else ""
    parent = lp[-2] if len(lp) >= 2 else ""
    dirs = lp[:-1]

    if parent == ".claude" and name in ("settings.json", "settings.local.json"):
        return "claude"
    if parent == ".vscode" and name == "settings.json":
        return "vscode"
    if parent == ".codex" and name == "config.toml":
        return "codex"
    if (parent, name) in {(".cursor", "mcp.json"), (".vscode", "mcp.json"), (".roo", "mcp.json"),
                          (".gemini", "settings.json"), (".cursor", "cli.json"), (".kiro", "mcp.json")} \
            or name == ".mcp.json" or (parent == ".continue" and name in ("config.json", "config.yaml", "config.yml")) \
            or name in (".aider.conf.yml", ".aider.conf.yaml"):
        return "config"
    if name in INSTRUCTION_NAMES or name.startswith((".roorules-", ".clinerules-")):
        if name == "copilot-instructions.md" and parent != ".github":
            return None
        return "instructions"

    def after(d: str) -> str | None:
        if d in dirs:
            i = dirs.index(d)
            return dirs[i + 1] if i + 1 < len(dirs) else ""
        return None

    md = ext in (".md", ".mdc", ".markdown")
    if after(".cursor") == "rules" and md:
        return "instructions"
    if after(".claude") is not None and md:
        return "instructions"
    if after(".github") in ("instructions", "prompts", "chatmodes", "agents") and md:
        return "instructions"
    if after(".windsurf") in ("rules", "workflows") and md:
        return "instructions"
    if ".clinerules" in dirs and ext in TEXT_EXT:
        return "instructions"
    nxt = after(".roo")
    if nxt is not None and nxt.startswith("rules") and ext in TEXT_EXT:
        return "instructions"
    if after(".continue") in ("rules", "prompts") and ext in TEXT_EXT:
        return "instructions"
    if after(".kiro") == "steering" and md:
        return "instructions"
    if after(".junie") is not None and name == "guidelines.md":
        return "instructions"
    if after(".gemini") is not None and md:
        return "instructions"
    if after(".amazonq") == "rules" and md:
        return "instructions"
    if after(".augment") == "rules" and md:
        return "instructions"
    if after(".idx") is not None and name == "airules.md":
        return "instructions"
    if after(".openhands") == "microagents" and md:
        return "instructions"
    if after(".trae") == "rules" and md:
        return "instructions"
    return None


def _classify_explicit(path: Path, text: str) -> str:
    kind = classify(path.as_posix())
    if kind:
        return kind
    suffix = path.suffix.lower()
    if suffix in (".json", ".jsonc"):
        if '"permissions"' in text and ('"allow"' in text or '"defaultMode"' in text):
            return "claude"
        if '"chat.tools.' in text:
            return "vscode"
        return "config"
    if suffix == ".toml":
        return "codex" if ("approval_policy" in text or "sandbox_mode" in text) else "config"
    return "instructions"


def _read(p: Path, max_bytes: int) -> str | None:
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_text(rel: str, text: str, kind: str) -> tuple[list[Finding], int]:
    """All checks for one file. Returns (findings, number suppressed by inline ignore comments)."""
    findings = scan_unicode(rel, text)
    if kind == "instructions":
        findings += scan_instructions(rel, text)
    elif kind == "claude":
        findings += scan_claude_settings(rel, text) or scan_generic_config(rel, text)
    elif kind == "vscode":
        findings += scan_vscode_settings(rel, text) or []
    elif kind == "codex":
        findings += scan_codex_toml(rel, text)
    else:
        findings += scan_generic_config(rel, text)
    lines = text.split("\n")
    kept, suppressed = [], 0
    for f in findings:
        if f.rule_id not in UNICODE_ONLY_RULES and f.line and IGNORE_MARK in lines[f.line - 1]:
            suppressed += 1
            continue
        kept.append(f)
    return kept, suppressed


def _add_file(path: Path, rel: str, kind: str, res: ScanResult, max_bytes: int) -> bool:
    text = _read(path, max_bytes)
    if text is None:
        return False
    res.files_scanned += 1
    (res.instruction_files if kind == "instructions" else res.config_files).append(rel)
    found, suppressed = scan_text(rel, text, kind)
    res.findings += found
    res.suppressed += suppressed
    return True


def tracked_files(root: Path) -> set[str] | None:
    """Paths (relative to root, '/'-separated) tracked by git, or None if not in a git work tree."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(root), "ls-files", "-z", "--", "."],
                           capture_output=True, timeout=30, env=env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return {p for p in r.stdout.decode("utf-8", errors="replace").split("\0") if p}


def _check_tracked(root: Path, rels: list[str], res: ScanResult, label_of=lambda r: r) -> None:
    tracked = tracked_files(root)
    if tracked is None:
        return
    lower = {t.lower() for t in tracked}
    for rel, key in rels:
        if Path(key).name.lower() in LOCAL_BY_DESIGN:
            continue
        if key not in tracked and key.lower() not in lower:
            res.findings.append(Finding(
                "RFA050", "low",
                f"{label_of(rel)} is not tracked by git: the agent loads it, but no change to it is ever reviewed.",
                rel, None, None))


def scan_path(target: str, *, excludes: list[str] | None = None, max_bytes: int = MAX_BYTES_DEFAULT,
              check_git: bool = True) -> ScanResult:
    excludes = excludes or []
    root = Path(target)
    if root.is_file():
        res = ScanResult(str(root.resolve().parent))
        text = _read(root, max_bytes)
        if text is not None:
            rel = target.replace("\\", "/")
            kind = _classify_explicit(Path(rel), text)
            if _add_file(root, rel, kind, res, max_bytes) and check_git and kind == "instructions":
                _check_tracked(root.resolve().parent, [(rel, root.name)], res)
        return res
    res = ScanResult(str(root.resolve()))
    found: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        inside_agent_dir = any(seg in AGENT_DOT_DIRS for seg in rel_dir.split("/"))
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                continue
            if d.startswith(".") and d not in AGENT_DOT_DIRS and not inside_agent_dir:
                continue
            if any(fnmatch.fnmatch(rel_dir + d, pat) or fnmatch.fnmatch(rel_dir + d + "/", pat) for pat in excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = rel_dir + fn
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            kind = classify(rel)
            if kind is None:
                continue
            if _add_file(Path(dirpath) / fn, rel, kind, res, max_bytes) and kind == "instructions":
                found.append((rel, rel))
    if check_git and found:
        _check_tracked(root, found, res)
    return res
