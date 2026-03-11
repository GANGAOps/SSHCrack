"""
mutations.py — Built-in passphrase mutation rules.

Generates common real-world password variations from a base word.
Optimised as a generator — no list allocation, yields one candidate at a time.

Coverage:
  • Case variants (original, capitalize, upper, lower, title)
  • Common numeric suffixes (1, 12, 123, 1234, 2023, 2024, 2025)
  • Common symbol suffixes (!, @, #, $, ., *)
  • Common prefixes (!, 1, The, My)
  • Leet speak substitutions (a→@, e→3, i→1, o→0, s→$)
  • Double-word (puppet → puppetpuppet)
  • Reversed word
  • Year patterns (word + 19XX, 20XX)
"""

from __future__ import annotations

from typing import Generator


# ── Leet speak table ──────────────────────────────────────────────────────────

_LEET_TABLE = str.maketrans({
    "a": "@", "A": "@",
    "e": "3", "E": "3",
    "i": "1", "I": "1",
    "o": "0", "O": "0",
    "s": "$", "S": "$",
    "t": "7", "T": "7",
    "l": "1", "L": "1",
    "g": "9", "G": "9",
    "b": "8", "B": "8",
})

# ── Common suffix/prefix lists ────────────────────────────────────────────────

_DIGIT_SUFFIXES = (
    "1", "2", "12", "123", "1234", "12345",
    "0", "01", "007",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "99", "100",
)

_SYMBOL_SUFFIXES = (
    "!", "@", "#", "$", "%", ".", "*", "?",
    "!1", "!!", "!@#",
    "#1", "@1",
)

_COMBINED_SUFFIXES = (
    "123!", "1!", "1234!", "2024!", "2025!",
    "123@", "1@", "2024@",
)

_PREFIXES = ("!", "1", "The", "My", "I")


# ── Core mutation generator ───────────────────────────────────────────────────

def apply_rules(word: str) -> Generator[str, None, None]:
    """
    Yield passphrase candidates derived from *word*.

    Order: most likely matches first to minimise average crack time.
    Deduplicates by tracking a seen set locally.
    """
    seen: set[str] = set()

    def _emit(candidate: str):
        if candidate not in seen:
            seen.add(candidate)
            return candidate
        return None

    def emit(c: str):
        v = _emit(c)
        if v is not None:
            yield v

    # ── Tier 1: Most common ───────────────────────────────────────────────────
    yield from emit(word)
    yield from emit(word.capitalize())
    yield from emit(word.upper())
    yield from emit(word.lower())
    yield from emit(word.title())

    # ── Tier 2: Numeric suffixes ──────────────────────────────────────────────
    for s in _DIGIT_SUFFIXES:
        yield from emit(word + s)
        yield from emit(word.capitalize() + s)

    # ── Tier 3: Symbol suffixes ───────────────────────────────────────────────
    for s in _SYMBOL_SUFFIXES:
        yield from emit(word + s)
        yield from emit(word.capitalize() + s)
        yield from emit(word.upper() + s)

    # ── Tier 4: Combined suffixes ─────────────────────────────────────────────
    for s in _COMBINED_SUFFIXES:
        yield from emit(word + s)
        yield from emit(word.capitalize() + s)

    # ── Tier 5: Prefixes ──────────────────────────────────────────────────────
    for p in _PREFIXES:
        yield from emit(p + word)
        yield from emit(p + word.capitalize())

    # ── Tier 6: Leet speak ────────────────────────────────────────────────────
    leet = word.translate(_LEET_TABLE)
    if leet != word:
        yield from emit(leet)
        yield from emit(leet.capitalize())
        for s in ("!", "1", "123"):
            yield from emit(leet + s)

    # ── Tier 7: Structural mutations ─────────────────────────────────────────
    yield from emit(word + word)           # doubled
    yield from emit(word[::-1])            # reversed
    yield from emit(word.swapcase())       # cAsE sWaP

    # ── Tier 8: Year patterns ─────────────────────────────────────────────────
    for decade in range(70, 100, 1):       # 19XX
        yield from emit(f"{word}19{decade:02d}")
    for year in range(0, 26):             # 20XX
        yield from emit(f"{word}20{year:02d}")


def count_rules() -> int:
    """
    Return approximate number of mutations generated per word.
    Used to estimate total candidate count before starting.
    """
    return sum(1 for _ in apply_rules("x"))
