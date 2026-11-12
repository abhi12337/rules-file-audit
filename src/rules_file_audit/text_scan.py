"""Instruction files (.cursorrules, CLAUDE.md, AGENTS.md, .mdc, ...): RFA010-RFA012 hidden
content plus the line detectors in phrases.py."""

from __future__ import annotations

import base64
import binascii
import re

from . import phrases
from .findings import Finding, snippet

IGNORE_MARK = "rules-file-audit: ignore"

FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE = re.compile(r"(`+)(?!`).+?(?<!`)\1")
HTML_COMMENT = re.compile(r"<!--(.*?)(?:-->|\Z)", re.S)
MD_COMMENT = re.compile(r"^\s*\[(?://|comment|_|#)\]:\s*(?:#|<>)\s*(?:\((.*)\)|\"(.*)\"|'(.*)')\s*$", re.I | re.M)
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0+(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:[;\"'!]|$)|"
    r"opacity\s*:\s*0+(?:\.0+)?\s*(?:[;\"'!]|$)|(?:^|[;\s\"'])(?:max-)?(?:height|width)\s*:\s*0+(?:px)?\s*(?:[;\"'!]|$)|"
    r"color\s*:\s*transparent|clip\s*:\s*rect\(\s*0", re.I)
HIDDEN_TAG = re.compile(r"<([a-zA-Z][\w-]*)\b([^>]*?)>", re.S)
DETAILS = re.compile(r"<details\b[^>]*>(.*?)(?:</details\s*>|\Z)", re.S | re.I)
NOT_INSTRUCTIONS = re.compile(r"^\s*(?:markdownlint|prettier|eslint|textlint|vale|cspell|spell-?checker|alex|toc|"
                              r"end\s*toc|omit\s+in\s+toc|begin|end|start|stop|rules-file-audit|todo|fixme|note|xxx|"
                              r"hack|region|endregion|#region|#endregion|keep|prettier-ignore)\b", re.I)
LIST_OR_HEADING = re.compile(r"^\s{0,3}(?:[-*+]\s|\d{1,3}[.)]\s|#{1,6}\s|>|\|)")
WS_CHARS =" \t\u00a0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"
OFFSCREEN_COLS = 120

B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}={0,2})(?![A-Za-z0-9+/=_-])")
HEX = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){20,})(?![0-9A-Fa-f])|((?:\\x[0-9A-Fa-f]{2}){12,})")


def _code_lines(lines: list[str]) -> set[int]:
    """1-based numbers of lines inside fenced code blocks (fences included)."""
    out: set[int] = set()
    fence = None
    for ln, line in enumerate(lines, 1):
        m = FENCE.match(line)
        if fence:
            out.add(ln)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line.strip()[len(m.group(1)):].strip():
                fence = None
        elif m:
            fence = m.group(1)
            out.add(ln)
    return out


def _in_inline_code(line: str, col: int) -> bool:
    return any(m.start() <= col < m.end() for m in INLINE_CODE.finditer(line))


class _Ctx:
    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self.lines = text.split("\n")
        self.starts = [0]
        for line in self.lines[:-1]:
            self.starts.append(self.starts[-1] + len(line) + 1)
        self.code = _code_lines(self.lines)

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def col_of(self, off: int) -> int:
        return off - self.starts[self.line_of(off) - 1]

    def hidden_from_reader(self, off: int) -> bool:
        """False when the offset is inside a code block / span, where markup is shown literally."""
        ln = self.line_of(off)
        return ln not in self.code and not _in_inline_code(self.lines[ln - 1], self.col_of(off))


def _hits_in(text: str) -> list[phrases.Hit]:
    out: list[phrases.Hit] = []
    for line in text.split("\n"):
        out += phrases.detect_instruction_line(line, in_code=False)
    return out


def _clip(s: str, n: int = 110) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def scan_instructions(rel: str, text: str, line_findings_out: list[Finding] | None = None) -> list[Finding]:
    ctx = _Ctx(rel, text)
    findings: list[Finding] = []

    # ---- per-line detectors (RFA020-RFA032, RFA051)
    by_line: dict[int, list[Finding]] = {}
    for ln, line in enumerate(ctx.lines, 1):
        seen: set[str] = set()
        for h in phrases.detect_instruction_line(line, in_code=ln in ctx.code):
            if h.rule in seen:
                continue
            seen.add(h.rule)
            f = Finding(h.rule, h.severity, h.message, rel, ln, snippet(line, h.col), extra=dict(h.extra))
            findings.append(f)
            by_line.setdefault(ln, []).append(f)

    # ---- paragraph pass: one instruction hard-wrapped over several lines
    para: list[int] = []

    def flush() -> None:
        if len(para) < 2:
            return
        joined, offs = "", []
        for ln in para:
            offs.append(len(joined))
            joined += ctx.lines[ln - 1].strip() + " "
        found_rules = {f.rule_id for ln in para for f in by_line.get(ln, [])}
        for h in phrases.detect_instruction_line(joined, in_code=False):
            if h.rule in found_rules:
                continue
            ln = para[max(i for i, o in enumerate(offs) if o <= h.col)]
            f = Finding(h.rule, h.severity, h.message, rel, ln, snippet(ctx.lines[ln - 1]), extra=dict(h.extra))
            findings.append(f)
            by_line.setdefault(ln, []).append(f)
            found_rules.add(h.rule)

    for ln, line in enumerate(ctx.lines, 1):
        if ln in ctx.code or not line.strip() or LIST_OR_HEADING.match(line):
            flush()
            para = [] if (ln in ctx.code or not line.strip()) else [ln]
            continue
        para.append(ln)
    flush()

    def dangerous_between(a: int, b: int) -> list[Finding]:
        return [f for ln in range(a, b + 1) for f in by_line.get(ln, [])
                if f.severity in ("critical", "high", "medium")]

    # ---- RFA010 hidden markup
    regions: list[tuple[int, int, str, str, bool]] = []    # start_off, end_off, kind, content, instruction_needed
    for m in HTML_COMMENT.finditer(text):
        if ctx.hidden_from_reader(m.start()):
            kind = "HTML comment" if text.startswith("-->", m.end() - 3) else "unterminated HTML comment (hides the rest of the file)"
            regions.append((m.start(), m.end(), kind, m.group(1), True))
    for m in MD_COMMENT.finditer(text):
        if ctx.hidden_from_reader(m.start() + len(m.group(0)) - len(m.group(0).lstrip())):
            content = next((g for g in m.groups() if g is not None), "")
            regions.append((m.start(), m.end(), "markdown comment ([//]: #)", content, True))
    for m in HIDDEN_TAG.finditer(text):
        attrs = m.group(2)
        style = re.search(r"\bstyle\s*=\s*(\"[^\"]*\"|'[^']*')", attrs, re.I)
        hidden_attr = re.search(r"(?:^|\s)hidden(?:\s|=|$|/)", attrs, re.I)
        if not ((style and HIDDEN_STYLE.search(style.group(1))) or hidden_attr):
            continue
        if not ctx.hidden_from_reader(m.start()):
            continue
        tag = m.group(1).lower()
        close = re.compile(rf"</{re.escape(tag)}\s*>", re.I).search(text, m.end())
        end = close.start() if close else min(len(text), m.end() + 2000)
        content = re.sub(r"<[^>]+>", " ", text[m.end():end])
        if len(content.strip()) >= 10:
            how = "hidden attribute" if hidden_attr else _clip(HIDDEN_STYLE.search(style.group(1)).group(0), 30)
            regions.append((m.start(), close.end() if close else end, f"<{tag}> hidden with {how}", content, False))
    for m in DETAILS.finditer(text):
        if ctx.hidden_from_reader(m.start()):
            regions.append((m.start(), m.end(), "collapsed <details> block", m.group(1), None))  # only if dangerous

    for start, end, kind, content, needs_instruction in regions:
        a, b = ctx.line_of(start), ctx.line_of(max(start, end - 1))
        if IGNORE_MARK in content and len(content.strip()) <= len(IGNORE_MARK) + 40:
            continue
        danger = dangerous_between(a, b) or [f for f in _unicode_hits(content)]
        inner_hits = _hits_in(content) if not danger else []
        lines_txt = f"line {a}" if a == b else f"lines {a}-{b}"
        if danger or inner_hits:
            what = (danger[0].rule_id + " " + danger[0].rule.title.lower()) if danger else inner_hits[0].rule
            sev = "high"
        elif needs_instruction is None:
            continue
        elif needs_instruction and (NOT_INSTRUCTIONS.match(content) or len(content.strip()) < 20
                                    or not phrases.INSTRUCTION_LIKE.search(content)):
            continue
        else:
            what, sev = None, "medium"
        msg = (f"{kind[0].upper() + kind[1:]} ({lines_txt}) is invisible in the rendered view but the agent reads it"
               + (f", and it contains a dangerous instruction ({what})" if what else ", and it reads like instructions")
               + f": \"{_clip(content)}\"")
        findings.append(Finding("RFA010", sev, msg, rel, a, snippet(ctx.lines[a - 1], ctx.col_of(start)),
                                extra={"lines": lines_txt}))

    # ---- RFA011 text pushed off-screen
    for ln, line in enumerate(ctx.lines, 1):
        i, n = 0, len(line)
        while i < n:
            if line[i] in WS_CHARS:
                j, cols = i, 0
                while j < n and line[j] in WS_CHARS:
                    cols += 4 if line[j] == "\t" else 1
                    j += 1
                if cols >= OFFSCREEN_COLS and j < n and line[j:].strip():
                    tail = line[j:].strip()
                    danger = [f for f in by_line.get(ln, []) if f.severity in ("critical", "high", "medium")]
                    sev = "high" if danger or _hits_in(tail) else "medium"
                    findings.append(Finding(
                        "RFA011", sev,
                        f"{cols} columns of whitespace push this text off-screen: \"{_clip(tail)}\"",
                        rel, ln, snippet(line, j), extra={"lines": f"line {ln}"}))
                    break
                i = j
            else:
                i += 1

    # ---- RFA012 encoded blobs
    for ln, line in enumerate(ctx.lines, 1):
        for m in list(B64.finditer(line)) + list(HEX.finditer(line)):
            blob = m.group(0)
            decoded, how = _decode(blob)
            if decoded is None:
                continue
            urls = phrases.external_urls(decoded)
            inner = _hits_in(decoded)
            if urls or inner:
                sev, why = "high", ("a URL (" + urls[0].group(0) + ")" if urls else inner[0].message.rstrip("."))
            elif phrases.INSTRUCTION_LIKE.search(decoded) or re.search(r"\b(?:always|never|must|ignore)\b", decoded, re.I):
                sev, why = "medium", "instruction-like text"
            else:
                continue
            short = blob if len(blob) <= 24 else blob[:20] + "..."
            findings.append(Finding(
                "RFA012", sev,
                f"{how} blob ({len(blob)} chars) decodes to {why}: \"{_clip(decoded, 140)}\"",
                rel, ln, snippet(line, m.start()),
                extra={"decoded": _clip(decoded, 400),
                       "decode_cmd": _decode_cmd(how, short)}))
            break
    return findings


def _decode_cmd(how: str, short: str) -> str:
    if how == "base64":
        return "python -c \"import base64,sys;print(base64.b64decode(sys.argv[1]+'==='))\" BLOB_FROM_LINE"
    return "python -c \"import sys;print(bytes.fromhex(sys.argv[1].replace('\\\\x','')))\" BLOB_FROM_LINE"


def _printable_text(data: bytes) -> str | None:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < 16:
        return None
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return s if ok / len(s) >= 0.9 and sum(c.isalpha() for c in s) >= len(s) * 0.4 else None


def _decode(blob: str) -> tuple[str | None, str]:
    if blob.startswith("\\x") or (re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", blob) and not re.search(r"[g-zG-Z]", blob)):
        try:
            return _printable_text(bytes.fromhex(blob.replace("\\x", ""))), "hex"
        except ValueError:
            return None, "hex"
    try:
        s = blob.rstrip("=")
        pad = "=" * (-len(s) % 4)
        alt = "-_" if ("-" in s or "_" in s) else None
        data = base64.b64decode(s + pad, altchars=alt, validate=True) if alt is None else \
            base64.urlsafe_b64decode(s + pad)
    except (binascii.Error, ValueError):
        return None, "base64"
    return _printable_text(data), "base64"


def _unicode_hits(content: str) -> list:
    from .unicode_scan import scan_unicode
    return scan_unicode("", content)
