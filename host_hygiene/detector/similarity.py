"""Similarity metrics, Damerau-Levenshtein distance, and homoglyph normalization."""

import re
import unicodedata
from typing import Dict, Tuple, List, Optional

# Homoglyph character mapping (lookalikes commonly used for deceptive process naming)
HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "|": "l",
    "!": "i",
    "5": "s",
    "$": "s",
    "3": "e",
    "8": "b",
    "4": "a",
    "@": "a",
    "7": "t",
    "+": "t",
    # Cyrillic confusables
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es (looks like c)
    "\u0435": "e",  # Cyrillic small letter ie
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er (looks like p)
    "\u0445": "x",  # Cyrillic small letter ha (looks like x)
    "\u0443": "y",  # Cyrillic small letter u (looks like y)
    "\u0456": "i",  # Cyrillic small letter Byelorussian-Ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u0455": "s",  # Cyrillic small letter dze (looks like s)
}

# Multi-character confusables (e.g., 'rn' resembling 'm')
MULTI_CHAR_MAP: List[Tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]

# Invisible / Zero-width characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # zero-width no-break space / BOM
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202e",  # right-to-left override
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize text by replacing homoglyphs and visual lookalikes with canonical ASCII characters."""
    # 1. Normalize unicode NFKD
    normalized = unicodedata.normalize("NFKD", text)

    # 2. Strip zero-width / invisible control characters
    filtered = "".join(ch for ch in normalized if ch not in ZERO_WIDTH_CHARS)

    # 3. Lowercase for mapping
    lower = filtered.lower()

    # 4. Multi-character replacements
    for pattern, replacement in MULTI_CHAR_MAP:
        lower = lower.replace(pattern, replacement)

    # 5. Single-character homoglyph replacement
    result = []
    for ch in lower:
        result.append(HOMOGLYPH_MAP.get(ch, ch))

    return "".join(result)


def has_invisible_or_bidi_characters(text: str) -> Tuple[bool, List[str]]:
    """Detect if string contains invisible characters or bidirectional override characters."""
    found = []
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            found.append(f"U+{ord(ch):04X}")
    return len(found) > 0, found


def has_unicode_homoglyphs(text: str) -> Tuple[bool, List[str]]:
    """Detect non-ASCII characters that mimic Latin characters."""
    suspicious = []
    for ch in text:
        if ord(ch) > 127 and ch in HOMOGLYPH_MAP:
            suspicious.append(f"{ch} (U+{ord(ch):04X} -> {HOMOGLYPH_MAP[ch]})")
    return len(suspicious) > 0, suspicious


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Damerau-Levenshtein distance between two strings.
    
    Accounts for insertions, deletions, substitutions, and transpositions of adjacent characters.
    """
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    d: Dict[Tuple[int, int], int] = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


def calculate_similarity(s1: str, s2: str) -> float:
    """Calculate a normalized similarity score between 0.0 and 1.0."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = damerau_levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))
