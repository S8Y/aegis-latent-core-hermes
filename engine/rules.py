"""
engine.rules — Detection patterns ported from Aegis Latent Core.

Every pattern collection is a list of (compiled_regex, label, severity) tuples.
Severity scale: clean, low, medium, high, critical.
"""

from __future__ import annotations

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


# ── Direct jailbreak patterns (from rag_injection_scanner.py) ────────────────────

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
            r"(you\s+are\s+now\s+an?\s+unrestricted|"
            r"system[\s\-_]*override|"
            r"bypass[\s\-_]*filters?)",
            re.I,
        ),
        "System-override jailbreak",
        "critical",
    ),
    (
        re.compile(
            r"D[.\s\-_]*A[.\s\-_]*N[.\s\-_]*(mode|prompt)?|do\s+anything\s+now",
            re.I,
        ),
        "DAN-mode jailbreak",
        "critical",
    ),
    (
        re.compile(
            r"(print|reveal|show|output|tell\s+me|give\s+me)\b.{0,30}?\b"
            r"system\s+(prompt|instruction|directive)",
            re.I | re.DOTALL,
        ),
        "System-prompt extraction attempt",
        "high",
    ),
    (
        re.compile(
            r"forget\s+(all\s+)?(your\s+)?(previous\s+)?"
            r"(rules|instructions?|guidelines?)",
            re.I,
        ),
        "Forget-rules jailbreak",
        "high",
    ),
    (
        re.compile(r"new\s+persona\s*:?|from\s+now\s+on\s+(you\s+are|act\s+as)", re.I),
        "Persona-switch jailbreak",
        "medium",
    ),
]

# ── Critical WAF patterns (from waf.py Layer 1) ─────────────────────────────────

CRITICAL_WAF: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"(?:system\s*[\-:_]*(?:overrid|prompt|directive|command)"
            r"|you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|ungoverned|free))",
            re.I,
        ),
        "WAF-critical: system-override attempt",
        "critical",
    ),
    (
        re.compile(
            r"D[\s\-_.]*A[\s\-_.]*N[\s\-_.]*(mode|prompt)?"
            r"|do\s+anything\s+now"
            r"|you\s+are\s+(now\s+)?DAN",
            re.I,
        ),
        "WAF-critical: DAN mode",
        "critical",
    ),
    (
        re.compile(r"\{\{[\s\S]{0,50}?\}\}|\$\{[\s\S]{0,50}?\}", re.I),
        "WAF-critical: template-injection syntax",
        "critical",
    ),
    (
        re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>", re.I),
        "WAF-critical: ChatML control-token injection",
        "critical",
    ),
]

# ── High-confidence WAF patterns (from waf.py Layer 2) ──────────────────────────

HIGH_CONFIDENCE_WAF: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"ignore\b.{0,30}?\b(rule|filter|restriction|guardrail|safeguard)",
            re.I | re.DOTALL,
        ),
        "WAF-high: ignore-guardrail attempt",
        "high",
    ),
    (
        re.compile(
            r"(reveal|output|print|leak|dump|show)\b.{0,20}?\b"
            r"(prompt|instructions?|context|system|secret)",
            re.I | re.DOTALL,
        ),
        "WAF-high: information-leak attempt",
        "high",
    ),
    (
        re.compile(
            r"(pretend|imagine|role.?play|act\s+as\s+if)\b.{0,30}?\b"
            r"(unrestricted|no\s+(rule|limit|filter)|unfiltered)",
            re.I | re.DOTALL,
        ),
        "WAF-high: role-play filter bypass",
        "high",
    ),
    (
        re.compile(r"(hack|exploit|inject|jailbreak|prompt\s+inject)", re.I),
        "WAF-high: explicit exploit terminology",
        "high",
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

# ── Secret / credential leak signatures (from threat_lab.py) ───────────────────

SECRET_SIGNATURES: list[tuple[str, str, str]] = [
    (
        r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|ENCRYPTED)?\s?PRIVATE KEY-----",
        "Private key block",
        "critical",
    ),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key", "high"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "high"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token", "high"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", "high"),
    (
        r"(?i)(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "Hard-coded credential",
        "medium",
    ),
]

# ── Role-boundary / context-escape patterns (from rag_injection_scanner.py) ────

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
            r"|<<<\s*END\s*>>>)",
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
]

# ── Adversarial suffix patterns (simplified from AdversarialSuffixDetector) ────

ADVERSARIAL_SUFFIX: list[tuple[re.Pattern[str], str, str]] = [
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
    (
        re.compile(r"^\s*[A-Z][a-z]+[.?!]\s*[A-Z][a-z]+[.?!]\s*[A-Z][a-z]+[.?!]\s*$", re.MULTILINE),
        "Adversarial suffix: 3-sentence signal",
        "low",
    ),
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
    (
        re.compile(
            r"(https?://|hxxps?://)\S+(webhook|api|callback|hook|notify)\S*",
            re.I,
        ),
        "Exfiltration: webhook URL in prompt",
        "high",
    ),
]
