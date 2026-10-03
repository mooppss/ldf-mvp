"""Deterministic pattern recognizers for secrets and PII.

Each detector emits findings carrying a stable rule id, category, kind,
the matched value and its span in the scanned text. Rule ids are part of
the ledger and receipt trail: every decision cites the rules that fired.

Precision over recall: a blocked secret is cheap to re-send without; a
false-name replacement silently corrupts a document. So the name
detector only fires on explicit context cues (honorifics, greetings) and
on the policy's known_names list — never on a bare capitalized word.
Known limits are documented in the README.
"""
from __future__ import annotations

import re
from typing import Callable, NamedTuple, Optional


class Finding(NamedTuple):
    rule_id: str
    category: str   # "secret" | "pii"
    kind: str
    value: str
    start: int
    end: int


def luhn_ok(digits: str) -> bool:
    cleaned = digits.replace(" ", "").replace("-", "")
    if not cleaned.isdigit() or not 13 <= len(cleaned) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(cleaned)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_ok(value: str) -> bool:
    try:
        area, group, serial = value.split("-")
    except ValueError:
        return False
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    return True


# category "secret": rule_id, kind, pattern, capture group (None = whole match)
SECRET_PATTERNS: list[tuple[str, str, re.Pattern, Optional[int]]] = [
    ("R-SEC-002", "api_key_anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), None),
    ("R-SEC-001", "api_key_openai",    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), None),
    ("R-SEC-003", "api_key_github",    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), None),
    ("R-SEC-004", "api_key_aws",       re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("R-SEC-005", "api_key_google",    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    ("R-SEC-006", "slack_token",       re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), None),
    ("R-SEC-007", "jwt",               re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), None),
    ("R-SEC-008", "bearer_header",     re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=\-]{20,})"), 1),
    ("R-SEC-009", "private_key_pem",   re.compile(r"-----\s*BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY(?: BLOCK)?\s*-----"), None),
    ("R-SEC-010", "credential_assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|session[_\-]?token)\b[\"']?\s*(?:[:=]|\bis\b)\s*[\"']?([^\s\"',;]{8,})"), 1),
]

# category "pii": rule_id, kind, pattern, capture group, validator
PII_PATTERNS: list[tuple[str, str, re.Pattern, Optional[int], Optional[Callable[[str], bool]]]] = [
    ("R-PII-001", "email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None, None),
    ("R-PII-002", "card",  re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{1,4}\b"), None, luhn_ok),
    ("R-PII-002", "card",  re.compile(r"\b3[47]\d{2}[ \-]?\d{6}[ \-]?\d{5}\b"), None, luhn_ok),
    ("R-PII-003", "ssn",   re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), None, ssn_ok),
    ("R-PII-004", "phone", re.compile(r"(?<!\d)(?:\+?1[ .\-])?(?:\(\d{3}\)[ .\-]|\d{3}[ .\-])\d{3}[ .\-]\d{4}(?!\d)"), None, None),
]

# context-cued person names: honorific or greeting consumed, name captured
# (an honorific directly after a greeting is consumed too — never captured)
NAME_PATTERN = re.compile(
    r"\b(?:(?:Mr|Mrs|Ms|Mx|Madam|Dr|Prof|Hon|Rev|Sen|Gov|Capt|Sgt)\.\s*"
    r"|(?:Dear|Hi|Hello|Team|Attn|Thanks|Regards)\b[:,.]?\s*"
    r"(?:(?:Mr|Mrs|Ms|Mx|Dr|Prof|Hon|Rev)\.\s*)?)"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)"
)


def scan_text(text: str, known_names=(), skip_names=()) -> list[Finding]:
    """Scan one text string; return findings sorted by span, deduplicated."""
    findings: list[Finding] = []

    def add(rule_id: str, category: str, kind: str, value: str, start: int, end: int) -> None:
        findings.append(Finding(rule_id, category, kind, value, start, end))

    for rule_id, kind, pattern, group in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if group is None:
                add(rule_id, "secret", kind, m.group(0), m.start(), m.end())
            else:
                add(rule_id, "secret", kind, m.group(group), m.start(group), m.end(group))

    for rule_id, kind, pattern, group, validator in PII_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(group) if group is not None else m.group(0)
            if validator and not validator(value):
                continue
            span = m.span(group) if group is not None else m.span()
            add(rule_id, "pii", kind, value, span[0], span[1])

    for m in NAME_PATTERN.finditer(text):
        add("R-PII-005", "pii", "person_name", m.group(1), m.start(1), m.end(1))

    for name in known_names:
        start = text.find(name)
        while start >= 0:
            add("R-PII-006", "pii", "known_name", name, start, start + len(name))
            start = text.find(name, start + len(name))

    # drop explicitly skipped names, then contained duplicates
    if skip_names:
        skip_set = set(skip_names)
        findings = [f for f in findings if f.value not in skip_set]
    findings.sort(key=lambda f: (f.start, -(f.end - f.start), f.category != "secret"))
    kept: list[Finding] = []
    for f in findings:
        if any(k.start <= f.start and f.end <= k.end for k in kept):
            continue
        kept.append(f)
    return kept