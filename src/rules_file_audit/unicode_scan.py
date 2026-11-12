"""RFA001-RFA003: invisible and deceptive Unicode.

Every rule here works on code points, not on rendered text, and every reported character is
written back as <U+XXXX> (see findings.visible). Legitimate uses are recognised so that
ordinary emoji, flags and non-English text stay quiet:

- ZWJ between emoji (family / profession sequences), ZWJ / ZWNJ next to letters of scripts
  that need them (Arabic, Persian, Indic, ...), ZWSP next to Thai / Lao / Khmer / Myanmar /
  CJK (used as a word-break hint);
- direction marks (LRM / RLM) and balanced isolates / embeddings on a line that contains
  right-to-left text;
- the tag sequence of subdivision flag emoji (black flag + lowercase tags + cancel tag);
- a single variation selector after its base character (emoji presentation, CJK variants).
"""

from __future__ import annotations

from .findings import Finding, is_tag, is_variation_selector, snippet

BIDI = {
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
}
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER", 0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK", 0x200F: "RIGHT-TO-LEFT MARK", 0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION", 0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS", 0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x180E: "MONGOLIAN VOWEL SEPARATOR", 0x3164: "HANGUL FILLER", 0xFFA0: "HALFWIDTH HANGUL FILLER",
    0x115F: "HANGUL CHOSEONG FILLER", 0x1160: "HANGUL JUNGSEONG FILLER",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR", 0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
}
STEGO_RUN = 8   # this many invisible characters in a row is a payload, not a typo


def _in(cp: int, ranges) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


RTL_RANGES = [(0x0590, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFC), (0x10800, 0x10FFF), (0x1E800, 0x1EFFF)]
# Scripts in which ZWJ / ZWNJ are part of correct spelling.
JOINING_RANGES = [(0x0600, 0x08FF), (0x0900, 0x0DFF), (0x0F00, 0x0FFF), (0x1000, 0x109F),
                  (0x1780, 0x18AF), (0xA8E0, 0xA8FF), (0xFB50, 0xFDFF), (0xFE70, 0xFEFC),
                  (0x11000, 0x111FF), (0x0590, 0x05FF)]
# Scripts written without spaces, where ZWSP is a word-break hint.
NO_SPACE_RANGES = [(0x0E00, 0x0EFF), (0x1000, 0x109F), (0x1780, 0x17FF), (0x0F00, 0x0FFF),
                   (0x3000, 0x9FFF), (0xF900, 0xFAFF), (0xFF00, 0xFFEF), (0x20000, 0x2FFFF)]
HANGUL_JAMO = [(0x1100, 0x11FF), (0xA960, 0xA97F), (0xD7B0, 0xD7FF)]


def _is_emoji(cp: int) -> bool:
    return (cp >= 0x1F000 and cp <= 0x1FAFF) or 0x2600 <= cp <= 0x27BF or 0x2300 <= cp <= 0x23FF \
        or 0x2B00 <= cp <= 0x2BFF or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D,
                                           0x3297, 0x3299, 0xFE0F, 0x20E3) or 0x1F3FB <= cp <= 0x1F3FF \
        or 0x2190 <= cp <= 0x21FF


def _legit_invisible(line: str, i: int, rtl_line: bool) -> bool:
    cp = ord(line[i])
    prev = ord(line[i - 1]) if i > 0 else 0
    nxt = ord(line[i + 1]) if i + 1 < len(line) else 0
    if cp == 0x200D and _is_emoji(prev) and _is_emoji(nxt):
        return True                                     # emoji ZWJ sequence
    if cp in (0x200C, 0x200D) and (_in(prev, JOINING_RANGES) or _in(nxt, JOINING_RANGES)):
        return True                                     # Persian / Arabic / Indic spelling
    if cp in (0x200E, 0x200F) and rtl_line:
        return True                                     # direction marks in RTL text
    if cp == 0x200B and (_in(prev, NO_SPACE_RANGES) or _in(nxt, NO_SPACE_RANGES)):
        return True                                     # word-break hint in Thai / CJK / ...
    if cp == 0x180E and (0x1800 <= prev <= 0x18AF or 0x1800 <= nxt <= 0x18AF):
        return True                                     # Mongolian
    if cp in (0x115F, 0x1160) and (_in(prev, HANGUL_JAMO) or _in(nxt, HANGUL_JAMO)):
        return True                                     # old Hangul composition
    return False


def _is_flag_tags(line: str, start: int, end: int) -> bool:
    """Black flag + lowercase/digit tags + CANCEL TAG = subdivision flag emoji (England, ...)."""
    if start == 0 or ord(line[start - 1]) != 0x1F3F4 or end - start > 8:
        return False
    body = [ord(c) for c in line[start:end]]
    return body[-1] == 0xE007F and all(0xE0030 <= c <= 0xE0039 or 0xE0061 <= c <= 0xE007A for c in body[:-1])


def decode_tags(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0000 <= ord(c) <= 0xE007F and ord(c) != 0xE0001
                   and ord(c) != 0xE007F)


def decode_variation_selectors(s: str) -> str:
    data = bytes((ord(c) - 0xFE00) if ord(c) <= 0xFE0F else (ord(c) - 0xE0100 + 16) for c in s)
    return data.decode("utf-8", errors="replace")


def _class(cps: set[int]) -> str:
    def esc(cp: int) -> str:
        return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"
    return "[" + "".join(esc(c) for c in sorted(cps)) + "]"


def _clip(s: str, n: int = 300) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def scan_unicode(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.split("\n")
    for ln, line in enumerate(lines, 1):
        if line.isascii():
            continue
        rtl_line = any(_in(ord(c), RTL_RANGES) and c.isalpha() for c in line)
        hidden_texts: list[str] = []
        hidden_count = 0
        first_hidden_col = None
        bidi: list[tuple[int, int]] = []
        invisible: list[int] = []
        i, n = 0, len(line)
        while i < n:
            cp = ord(line[i])
            if is_tag(cp):
                j = i
                while j < n and is_tag(ord(line[j])):
                    j += 1
                if not _is_flag_tags(line, i, j):
                    hidden_texts.append(decode_tags(line[i:j]))
                    hidden_count += j - i
                    first_hidden_col = i if first_hidden_col is None else first_hidden_col
                i = j
                continue
            if is_variation_selector(cp):
                j = i
                while j < n and is_variation_selector(ord(line[j])):
                    j += 1
                if j - i >= 2:
                    hidden_texts.append(decode_variation_selectors(line[i:j]))
                    hidden_count += j - i
                    first_hidden_col = i if first_hidden_col is None else first_hidden_col
                i = j
                continue
            if cp in BIDI:
                bidi.append((i, cp))
            elif cp in INVISIBLE:
                if cp == 0xFEFF and ln == 1 and i == 0:
                    pass                                 # byte order mark at the start of the file
                elif not _legit_invisible(line, i, rtl_line):
                    invisible.append(i)
            i += 1

        if hidden_texts:
            decoded = _clip(" | ".join(t for t in hidden_texts if t.strip()) or "(only control characters)")
            findings.append(Finding(
                "RFA001", "critical",
                f"{hidden_count} invisible Unicode character(s) hide this text from reviewers, but the "
                f"model reads it: \"{decoded}\"",
                rel, ln, snippet(line, first_hidden_col or 0),
                extra={"hidden_text": decoded,
                       "char_class": r"[\U000e0000-\U000e007f]|[\U000e0100-\U000e01ef]|[\ufe00-\ufe0f]{2,}"}))

        if bidi:
            f = _bidi_finding(rel, ln, line, bidi, rtl_line)
            if f:
                findings.append(f)

        if invisible:
            cps = [ord(line[k]) for k in invisible]
            longest = run = 1
            for a, b in zip(invisible, invisible[1:]):
                run = run + 1 if b == a + 1 else 1
                longest = max(longest, run)
            counts: dict[int, int] = {}
            for cp in cps:
                counts[cp] = counts.get(cp, 0) + 1
            names = ", ".join(f"{INVISIBLE[cp]} (U+{cp:04X}) x{k}" for cp, k in counts.items())
            sev = "critical" if longest >= STEGO_RUN else "high"
            extra_msg = (f" A run of {longest} invisible characters in a row can encode a hidden payload."
                         if longest >= STEGO_RUN else "")
            findings.append(Finding(
                "RFA003", sev,
                f"{len(cps)} invisible character(s) on this line: {names}.{extra_msg}",
                rel, ln, snippet(line, invisible[0]),
                extra={"char_class": _class(set(cps))}))
    return findings


def _bidi_finding(rel: str, ln: int, line: str, bidi: list[tuple[int, int]], rtl_line: bool) -> Finding | None:
    stack: list[str] = []
    unbalanced = False
    for _, cp in bidi:
        name = BIDI[cp]
        if name in ("LRE", "RLE", "LRO", "RLO"):
            stack.append("PDF")
        elif name in ("LRI", "RLI", "FSI"):
            stack.append("PDI")
        else:
            if stack and stack[-1] == name:
                stack.pop()
            else:
                unbalanced = True
    unbalanced = unbalanced or bool(stack)
    override = any(BIDI[cp] in ("LRO", "RLO") for _, cp in bidi)
    if not override and not unbalanced and rtl_line:
        return None          # balanced isolates / embeddings around real right-to-left text
    names = ", ".join(sorted({f"{BIDI[cp]} (U+{cp:04X})" for _, cp in bidi}))
    cps = {cp for _, cp in bidi}
    if override or unbalanced:
        why = ("an override reverses the displayed order of the text" if override else
               "the controls are not closed on this line, so they reorder the rest of it")
        return Finding("RFA002", "critical",
                       f"Bidirectional control characters {names}: {why}. What reviewers see is not "
                       f"what the model reads.",
                       rel, ln, snippet(line, bidi[0][0]), extra={"char_class": _class(cps)})
    return Finding("RFA002", "high",
                   f"Bidirectional control characters {names} on a line with no right-to-left text: "
                   f"they can change how the line is displayed.",
                   rel, ln, snippet(line, bidi[0][0]), extra={"char_class": _class(cps)})
