"""Shared helpers.

Invisible characters are never written literally in this repository: every test builds
them from code points at runtime. Hostile instructions only exist inside tmp folders that
the tests create, so no agent working on this repository ever loads them.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

ZWSP, ZWNJ, ZWJ = chr(0x200B), chr(0x200C), chr(0x200D)
LRM, RLM = chr(0x200E), chr(0x200F)
VS16 = chr(0xFE0F)
RLO, LRE, PDF = chr(0x202E), chr(0x202A), chr(0x202C)
RLI, PDI = chr(0x2067), chr(0x2069)
BOM = chr(0xFEFF)


def tags(s: str) -> str:
    """ASCII -> Unicode tag characters (invisible)."""
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def vs_encode(data: bytes) -> str:
    """Bytes -> stacked variation selectors (the 'emoji smuggling' encoding)."""
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in data)


def has_invisible(s: str) -> bool:
    import unicodedata
    for ch in s:
        cp = ord(ch)
        if ch in "\n\r\t":
            continue
        if 0xE0000 <= cp <= 0xE01EF or 0xFE00 <= cp <= 0xFE0F or cp in (0x3164, 0xFFA0, 0x115F, 0x1160, 0x180E):
            return True
        if unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cs", "Zl", "Zp"):
            return True
    return False


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content" | dict, ...}) -> Path. dict values are written as JSON."""

    def _make(files: dict, name: str = "repo") -> Path:
        root = tmp_path / name
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            p.write_text(content, encoding="utf-8", newline="\n")
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy
