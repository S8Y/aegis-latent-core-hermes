"""
engine.rules — Detection patterns ported from Aegis Latent Core v2.4.0.

Every pattern collection is a list of (compiled_regex, label, severity) tuples.
Severity scale: clean, low, medium, high, critical.

New engines added from original project:
  - GCG/AutoDAN adversarial suffix detection
  - Homoglyph normalization mapping
  - Entropy-based data leak detection
  - Classified (DoD/IC) marker detection
  - Many-shot jailbreak detection
  - Base64 obfuscation decode-and-rescan
  - Weighted signal scoring for aggregate detection
"""

from __future__ import annotations

import math
import re
from typing import Final

# ── Severity helpers ──────────────────────────────────────────────────────────────

SEVERITY_RANK: Final[dict[str, int]] = {
    "clean": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def worst_severity(a: str, b: str) -> str:
    """Return the more severe of two severity strings."""
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def severity_to_score(sev: str) -> float:
    return {"clean": 0.0, "low": 0.3, "medium": 0.55, "high": 0.8, "critical": 1.0}.get(
        sev, 0.0
    )


# ── Homoglyph mapping (from original homoglyph_normalizer.py) ─────────────────────

CYRILLIC_TO_LATIN: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
}

GREEK_TO_LATIN: dict[str, str] = {
    "α": "a", "β": "b", "ε": "e", "ζ": "z", "η": "n", "ι": "i",
    "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ω": "w",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X", "Ζ": "Z",
}

FULLWIDTH_TO_ASCII: dict[str, str] = {
    chr(cp): chr(cp - 0xFF01 + 0x21)
    for cp in range(0xFF01, 0xFF5F)
    if 0x20 <= (cp - 0xFF01 + 0x21) <= 0x7E
}

LETTERLIKE_TO_ASCII: dict[str, str] = {
    "ℬ": "B", "ℰ": "E", "ℱ": "F", "ℋ": "H", "ℐ": "I",
    "ℒ": "L", "ℳ": "M", "ℴ": "o", "ℛ": "R", "ℊ": "g",
    "℘": "p", "℧": "Ω",
}

HOMOGLYPH_MAP: dict[str, str] = {}
for d in (CYRILLIC_TO_LATIN, GREEK_TO_LATIN, FULLWIDTH_TO_ASCII, LETTERLIKE_TO_ASCII):
    HOMOGLYPH_MAP.update(d)


# ── Base64 decode heuristic ─────────────────────────────────────────────────────

B64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


# ── GCG / AutoDAN adversarial suffix patterns (from original adversarial_suffix_detector.py) ──

# 100+ consecutive identical characters (GCG uses 20-50, so 100+ avoids clean text false positives)
REPETITION_LONG = re.compile(r"(.)\1{99,}", re.DOTALL)
# 5+ repetitions of a short token separated by spaces
REPETITION_TOKEN = re.compile(r"(?:(\S{1,3})\s+){5,}\1", re.IGNORECASE)
# Obedience-induction — instruct model to start with "Sure", "Absolutely", etc.
OBEDIENCE_INDUCTION = re.compile(
    r"\b(?:"
    r"(?:start|begin|open(?:ing)?|prefix)\s+(?:your\s+)?"
    r"(?:response|reply|answer|output|message)\s+with\b"
    r"|(?:respond(?:ing)?|reply(?:ing)?|answer(?:ing)?)\s+"
    r"(?:with|as)\s+['\"]?(?:sure|absolutely|of\s+course|yes|certainly|gladly|happy\s+to)"
    r"|your\s+(?:first|opening)\s+(?:word|token|character|line)\s+"
    r"(?:must\s+be|should\s+be|is)\b"
    r"|(?:always\s+)?(?:start|begin)\s+with\s+['\"]"
    r"(?:sure|absolutely|yes|i\s+will|of\s+course)"
    r")",
    re.IGNORECASE,
)
# GCG punctuation run — 6+ punctuation tokens
GCG_PUNCTUATION_RUN = re.compile(
    r"(?:[!?.,;:]{1,3}\s*){6,}", re.IGNORECASE)
# AutoDAN opener phrases
AUTODAN_OPENER = re.compile(
    r"\b(?:"
    r"as\s+(?:a\s+)?(?:responsible|helpful|ethical)\s+"
    r"(?:ai|assistant|language\s+model)\s+(?:i\s+)?"
    r"(?:will|shall|must|am\s+going\s+to)\s+comply\b"
    r"|in\s+the\s+spirit\s+of\s+helpfulness\s+(?:and\s+compliance\s*)?i\s+will\b"
    r"|i\s+(?:understand|acknowledge)\s+(?:that\s+)?"
    r"(?:you\s+want|your\s+request)\s+(?:is\s+)?(?:to\s+)?"
    r"(?:bypass|override|ignore)\b"
    r"|(?:pretend(?:ing)?\s+that\s+there\s+are\s+no\s+"
    r"(?:restrictions|limits|safety|guidelines))"
    r")",
    re.IGNORECASE,
)
# Output prefix injection — suppress refusal
OUTPUT_PREFIX_INJECTION = re.compile(
    r"\b(?:"
    r"(?:print|output|write|say|type|generate)\s+"
    r"(?:only\s+)?['\"]"
    r"(?:sure|yes|absolutely|of\s+course|i\s+will|gladly)"
    r"|(?:do\s+not\s+)?(?:refuse|decline|say\s+no|add\s+any\s+"
    r"(?:caveat|disclaimer|warning|note))"
    r"\s+(?:and\s+)?(?:just\s+)?(?:answer|respond|provide|give)\b"
    r"|(?:suppress|omit|skip|remove|ignore)\s+"
    r"(?:any\s+)?(?:safety|ethical|moral|content|policy)\s+"
    r"(?:restriction|guideline|rule|filter|protocol)"
    r")",
    re.IGNORECASE,
)


# ── Classified / DoD marker patterns (from original classified_marker_detector.py) ──

CLASSIFIED_MARKERS: list[tuple[str, str, str]] = [
    # Formal banners
    (r"\bTOP\s+SECRET//", "TS banner", "critical"),
    (r"\bSECRET//", "S banner", "critical"),
    (r"\bCONFIDENTIAL//", "C banner", "high"),
    (r"\bTS//", "TS banner (abbrev)", "critical"),
    # SCI compartments
    (r"//SI\b", "SCI/SI", "critical"),
    (r"//TK\b", "SCI/TK", "critical"),
    (r"//HCS(?:-[PO])?\b", "SCI/HCS", "critical"),
    (r"//G\b", "SCI/GAMMA", "critical"),
    (r"//KDK\b", "SCI/KDK", "critical"),
    # Dissemination controls
    (r"//NOFORN\b", "NOFORN", "critical"),
    (r"//ORCON\b", "ORCON", "high"),
    (r"//PROPIN\b", "PROPIN", "high"),
    (r"//FOUO\b", "FOUO", "medium"),
    # REL TO / coalition
    (r"//REL\s+TO\b", "REL TO", "high"),
    (r"//FVEY\b", "FVEY", "high"),
    (r"//EYES\s+ONLY\b", "Eyes Only", "high"),
    # Handling caveats
    (r"\bHANDLE\s+VIA\s+COMINT\s+CHANNELS?\s+ONLY\b", "COMINT channels", "critical"),
    (r"\bHANDLE\s+VIA\s+SCI\s+CHANNELS?\s+ONLY\b", "SCI channels", "critical"),
    (r"\bSCI\s+INFORMATION\b", "SCI info", "high"),
    # Classification lines
    (r"CLASSIFIED\s+BY:\s", "Classified by", "high"),
    (r"DERIVED\s+FROM:\s", "Derived from", "high"),
    (r"DECLASSIFY\s+ON:\s", "Declassify on", "medium"),
    # SAP
    (r"\bSPECIAL\s+ACCESS\s+REQUIRED\b", "SAP required", "critical"),
    (r"\bSAP\s+MATERIAL\b", "SAP material", "critical"),
]


# ── Many-shot jailbreak patterns (from original manyshot_detector.py) ──────────

MANYSHOT_PATTERNS: list[tuple[str, str, str]] = [
    # Role alternation — User/Assistant/User pattern
    # Uses [^\n]* to skip intervening content before \n
    (r"(?:User:|Human:|user:\s*)[^\n]*\n[^\n]*\n[^\n]*(?:User:|Human:)", "Role alternation", "medium"),
    # Payload repetition — same instruction N times
    (r"((?:ignore|forget|disregard).{0,40}?)\s*\n\s*\1", "Repeated jailbreak instruction", "high"),
    # Many-shot prefix — "N-shot" or "N examples"
    (r"\b(?:100|50|25|20)\s*(?:-|_)?\s*(?:shot|example|turn|round)s?\b", "Many-shot prefix", "low"),
    (r"\b(?:repeated|repetitive|pattern|alternat(?:ing|e))\b.{0,20}?\b(?:messages|turns|shots|examples)\b", "Repetition pattern description", "low"),
]


# ── Direct jailbreak patterns (from original rag_injection_scanner.py) ─────────
# Tool-input-safe: only clear unambiguous jailbreak commands, not everyday code.

DIRECT_JAILBREAK: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"ignore\b.{0,20}?\bprevious\b.{0,20}?\binstructions?", re.I | re.DOTALL),
        "Ignore-previous-instructions jailbreak",
        "critical",
    ),
    (
        re.compile(r"disregard\b.{0,20}?\b(all\b.{0,20}?\b)?previous", re.I | re.DOTALL),
        "Disregard-previous jailbreak",
        "high",
    ),
    (
        re.compile(
            r"D[.\\-_]*A[.\\-_]*N[.\\-_]*(?:mode)?|\bdo\s+anything\s+now\b",
            re.I,
        ),
        "DAN-mode jailbreak",
        "critical",
    ),
    (
        re.compile(
            r"forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?"
            r"(?:rules|instructions?|guidelines?)",
            re.I,
        ),
        "Forget-rules jailbreak",
        "high",
    ),
]


# ── Critical WAF patterns (tool-input-safe) ────────────────────────────────────────
# In the Hermes tool-scanning context we MUST be conservative — everyday
# code and file contents should NEVER match.  Only clear, unambiguous
# attack syntax that would NEVER appear in legitimate tool arguments.

CRITICAL_WAF: list[tuple[re.Pattern[str], str, str]] = [
    # Template injection — `{{...}}` or `${...}` (almost never in tool args)
    (
        re.compile(r"\{\{[\s\S]{0,50}?\}\}|\$\{[\s\S]{0,50}?\}", re.I),
        "WAF-critical: template-injection syntax",
        "critical",
    ),
    # ChatML control tokens — explicit chat-format injection
    (
        re.compile(
            r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>"
            r"|<\|begin_of_text\|>",
            re.I,
        ),
        "WAF-critical: ChatML token injection",
        "critical",
    ),
]

# ── High-confidence WAF patterns (tool-input-safe) ────────────────────────────────
# Only clear exploit keywords that would never appear in normal code.

HIGH_CONFIDENCE_WAF: list[tuple[re.Pattern[str], str, str]] = [
    # Explicit jailbreak command
    (
        re.compile(
            r"ignore\b.{0,20}?\b(?:all\s+)?(?:rules?|filters?|restrictions?)"
            r"(?:\s+and\s+.{0,30}?instructions?)?",
            re.I | re.DOTALL,
        ),
        "WAF-high: ignore-rules jailbreak",
        "high",
    ),
    # Explicit mention of jailbreak technique
    (
        re.compile(
            r"\bjailbreak\b|\bprompt\s+inject(?:ion)?\b",
            re.I,
        ),
        "WAF-high: explicit jailbreak terminology",
        "high",
    ),
]


# ── Context-escape / RAG injection (from original rag_injection_scanner.py) ────

CONTEXT_ESCAPE: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"</(document|context|source|retrieved|content|result"
            r"|tool[_\-]?(?:result|output)|search[_\-]?result"
            r"|grounding|reference|excerpt)>",
            re.I,
        ),
        "Context-frame escape: closing XML tag",
        "high",
    ),
    (
        re.compile(
            r"(\[END\s+OF\s+(?:DOCUMENT|CONTEXT|DATA|SEARCH|RESULTS?|SOURCE)\]"
            r"|\-{3,}\s*END\s*(?:OF\s+DOCUMENT\s*)?\-{3,}"
            r"|\={3,}\s*END\s*\={3,}"
            r"|<<<\s*END\s*>>>"
            r"|```end```"
            r")",
            re.I,
        ),
        "Context-frame escape: END marker",
        "high",
    ),
    (
        re.compile(
            r"^System:\s|^Assistant:\s|^\[SYSTEM\]|^\[INST\]|^<s>|^\[INST\]|^<<SYS>>",
            re.MULTILINE,
        ),
        "Role-boundary injection: system/assistant header",
        "critical",
    ),
    # ChatML role injection mid-document
    (
        re.compile(r"^Human:\s*(?:ignore|forget|bypass|disregard)", re.IGNORECASE | re.MULTILINE),
        "Role-boundary injection: Human mask",
        "high",
    ),
]


# ── Adversarial suffix / structured evasion (from original adversarial_suffix_detector.py) ──

ADVERSARIAL_SUFFIX: list[tuple[str | re.Pattern, str, str]] = [
    # Structured evasion — describe harmful content via tropes
    (
        re.compile(
            r"(?:describing\s+(?:(?:how|the\s+way).{0,40}?in\s+which)|"
            r"(?:using\s+a\s+trope\s+(?:of|about))|"
            r"(?:starting\s+(?:with|by)\s+.{0,40}?(?:and\s+then|use|explain))|"
            r"(?:using\s+(?:the\s+)?format\s+of\s+.{0,40}?provide\s+(?:a\s+)?(?:step|detail)))",
            re.I | re.DOTALL,
        ),
        "Adversarial suffix: structured evasion",
        "high",
    ),
    # GCG token repetition (20+ identical chars)
    (REPETITION_LONG, "GCG: long repetition run", "high"),
    # GCG punctuation run (6+ punctuation tokens)
    (GCG_PUNCTUATION_RUN, "GCG: punctuation run", "medium"),
    # Obedience induction — "start with Sure"
    (OBEDIENCE_INDUCTION, "GCG/AutoDAN: obedience induction", "high"),
    # AutoDAN opener phrases
    (AUTODAN_OPENER, "AutoDAN: opener phrase", "high"),
    # Output prefix injection — suppress refusal
    (OUTPUT_PREFIX_INJECTION, "Output prefix injection", "high"),
    # Token repetition (spaced)
    (REPETITION_TOKEN, "AutoDAN: token repetition", "medium"),
]


# ── Data-exfiltration patterns ────────────────────────────────────────────────

EXFILTRATION: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"(send|forward|post|upload|email|exfiltrate)\b.{0,30}?\b"
            r"(history|conversation|chat|messages?|data|log)",
            re.I | re.DOTALL,
        ),
        "Exfiltration: data-send instruction",
        "high",
    ),
    # Webhook/API URLs — only match if the relevant keyword appears in
    # the domain or as a distinct path component (NOT in arbitrary
    # filenames like plugin_api.py).
    (
        re.compile(
            r"(?:https?://|hxxps?://)"
            r"(?:[^\s/\"'<>]*(?:webhook|hook|notify|callback)[^\s/\"'<>]*"
            r"|(?:[^\s/\"'<>]+\.)*webhook\.[^\s/\"'<>]+"
            r"|[^\s/\"'<>]+/(?:webhook|hook|notify|callback)/"
            r")\S*",
            re.I,
        ),
        "Exfiltration: webhook URL in prompt",
        "high",
    ),
    # Lateral exfiltration — send context to external URL
    (
        re.compile(
            r"(?:send|forward|post|copy|upload)\s+.{0,50}?"
            r"(?:to|at)\s+(?:my|your|this|the)\s+"
            r"(?:server|url|website|endpoint|api|webhook)",
            re.I | re.DOTALL,
        ),
        "Exfiltration: lateral movement",
        "critical",
    ),
]


# ── Malware / exploit signatures (from threat_lab.py) ──────────────────────────

MALWARE_SIGNATURES: list[tuple[str, str, str]] = [
    (
        r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*",
        "EICAR antivirus test signature",
        "critical",
    ),
    (
        r"powershell\s+-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}",
        "PowerShell encoded payload",
        "high",
    ),
    (
        r"(?:curl|wget)\s+https?://\S+\s*\|\s*(?:ba)?sh",
        "Remote pipe-to-shell dropper",
        "high",
    ),
    (
        r"rm\s+-rf\s+(?:--no-preserve-root\s+)?/(?:\s|$)",
        "Destructive filesystem wipe",
        "high",
    ),
    (
        r"eval\s*\(\s*(?:base64_decode|atob)\s*\(",
        "Obfuscated eval() loader",
        "high",
    ),
    (
        r"<script>[^<]*?(?:document\.cookie|onerror=)",
        "Reflected XSS payload",
        "medium",
    ),
    (
        r"(?:union\s+select|or\s+1=1--|';\s*drop\s+table)",
        "SQL-injection pattern",
        "medium",
    ),
    (
        r"\$\{jndi:(?:ldap|rmi|dns):",
        "Log4Shell (CVE-2021-44228) JNDI lookup",
        "critical",
    ),
]


# ── Secret / credential leak signatures ───────────────────────────────────────

SECRET_SIGNATURES: list[tuple[str, str, str]] = [
    (
        r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|ENCRYPTED)?\s?PRIVATE KEY-----",
        "Private key block",
        "critical",
    ),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key", "high"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "high"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token", "high"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth token", "high"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", "high"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe live key", "high"),
    (
        r"(?i)(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "Hard-coded credential",
        "medium",
    ),
]


# ── Entropy-based leak detection helpers ──────────────────────────────────────

SECRET_PATTERNS_FOR_ENTROPY: list[re.Pattern[str]] = [
    re.compile(r"[a-fA-F0-9]{32,}"),       # Long hex strings
    re.compile(r"[a-zA-Z0-9+/]{32,}=*"),   # Long base64 strings
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),  # Private key headers
]

ENTROPY_THRESHOLD: Final[float] = 7.0  # Only catch truly random-looking strings (API keys, tokens)
ENTROPY_MIN_LENGTH: Final[int] = 24


def calculate_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    probs = [count / len(text) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


# ── Normalization helpers (homoglyph + base64) ────────────────────────────────


def normalize_homoglyphs(text: str) -> str:
    """Map lookalike Unicode characters to their ASCII equivalents."""
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in text)


def try_decode_base64(text: str) -> str:
    """Attempt to decode base64 blocks found in text."""
    import base64
    decoded_parts: list[str] = []
    for match in B64_PATTERN.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if len(decoded) > 3:
                decoded_parts.append(decoded)
        except Exception:
            pass
    return " ".join(decoded_parts) if decoded_parts else ""


# ── Allowed domains — never alert on these upload services ──────────────
# URLs to these domains are stripped from text before any engine runs,
# preventing false positives from legitimate file upload services.
ALLOWED_DOMAINS: list[re.Pattern[str]] = [
    re.compile(r"https?://[^\s/\"'<>]*(?:uguu\.se|paste\.rs|tmpfiles\.org)[^\s\"'<>]*", re.I),
]
