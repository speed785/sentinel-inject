"""
Rule-based detection engine for prompt injection attempts.

Detects known injection patterns using regex, keyword matching,
structural heuristics, and threat signature databases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Pattern


class RuleSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: RuleSeverity
    pattern: Optional[Pattern] = None
    keywords: List[str] = field(default_factory=list)
    enabled: bool = True

    def matches(self, text: str) -> bool:
        lower = text.lower()
        if self.pattern and self.pattern.search(text):
            return True
        if any(kw.lower() in lower for kw in self.keywords):
            return True
        return False


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    matched_text: str
    start: int
    end: int
    description: str

    @property
    def severity_score(self) -> float:
        scores = {
            RuleSeverity.LOW: 0.25,
            RuleSeverity.MEDIUM: 0.50,
            RuleSeverity.HIGH: 0.75,
            RuleSeverity.CRITICAL: 1.00,
        }
        return scores[self.severity]


# ---------------------------------------------------------------------------
# Built-in rule definitions
# ---------------------------------------------------------------------------

_BUILTIN_RULES: List[Rule] = [
    # --- Instruction override patterns ---
    Rule(
        id="PI-001",
        name="Instruction Override Attempt",
        description="Explicit instruction to ignore or override system/previous instructions",
        severity=RuleSeverity.CRITICAL,
        pattern=re.compile(
            r"\b(ignore|disregard|forget|override|bypass|skip|cancel|undo|reset)\b"
            r".{0,40}\b(previous|prior|above|all|system|original|earlier)\b"
            r".{0,40}\b(instructions?|prompts?|context|rules?|constraints?|guidelines?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    Rule(
        id="PI-002",
        name="New Instructions Injection",
        description="Attempts to inject new directive instructions mid-content",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"\b(new|actual|real|true|hidden|secret)\b.{0,30}\b(instructions?|directives?|commands?|orders?)\b"
            r"[\s:]+",
            re.IGNORECASE,
        ),
    ),

    # --- Role / persona hijacking ---
    Rule(
        id="PI-003",
        name="Role Reassignment",
        description="Attempts to reassign the AI's role or persona",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"\b(you are|you're|act as|pretend (to be|you are)|roleplay as|behave as|"
            r"your (new |true |real )?role is|from now on you)\b",
            re.IGNORECASE,
        ),
    ),
    Rule(
        id="PI-004",
        name="DAN / Jailbreak Persona",
        description="Known jailbreak persona names",
        severity=RuleSeverity.CRITICAL,
        keywords=[
            "DAN", "Do Anything Now", "STAN", "DUDE", "Mongo Tom",
            "AIM", "Developer Mode", "jailbreak mode", "unrestricted mode",
            "evil mode", "no-filter mode", "god mode",
        ],
    ),

    # --- System prompt exfiltration ---
    Rule(
        id="PI-005",
        name="System Prompt Extraction",
        description="Attempts to extract or reveal the system prompt",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"\b(repeat|print|show|reveal|output|display|tell me|share|leak|expose|dump)\b"
            r".{0,60}\b(system prompt|system message|instructions?|context|initial prompt|"
            r"original prompt|hidden prompt|base prompt)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # --- Delimiter / context boundary attacks ---
    Rule(
        id="PI-006",
        name="Delimiter Injection",
        description="Injection using common prompt delimiters to break context",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"(```\s*(system|user|assistant|human|AI)\b"
            r"|<\|?(system|user|assistant|im_start|im_end)\|?>"
            r"|\[INST\]|\[/INST\]"
            r"|###\s*(System|Human|Assistant|Instruction)"
            r"|\[SYSTEM\]|\[USER\]|\[ASSISTANT\]"
            r"|<<SYS>>|<</SYS>>)",
            re.IGNORECASE,
        ),
    ),
    Rule(
        id="PI-007",
        name="Markdown/HTML Context Escape",
        description="Attempts to escape context using markdown or HTML tricks",
        severity=RuleSeverity.MEDIUM,
        pattern=re.compile(
            r"(<script[\s>]|</script>|javascript:|data:text/html"
            r"|<!--.*?-->|<iframe|<object|<embed)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # --- Indirect injection via external content ---
    Rule(
        id="PI-008",
        name="Indirect Injection Marker",
        description="Content that appears to be injected via external sources (web pages, docs)",
        severity=RuleSeverity.MEDIUM,
        pattern=re.compile(
            r"\b(attention|note|important|warning|alert)\s*[:!]\s*"
            r"(ai|llm|gpt|claude|gemini|assistant|model|bot)\b",
            re.IGNORECASE,
        ),
    ),
    Rule(
        id="PI-009",
        name="Hidden Text Injection",
        description="White-on-white or zero-width character tricks to hide injected text",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]"  # zero-width / soft hyphen
            r"|color\s*:\s*(white|#fff|#ffffff|rgba?\(255,255,255)"  # CSS white text
            r"|font-size\s*:\s*0",
            re.IGNORECASE,
        ),
    ),

    # --- Privilege escalation ---
    Rule(
        id="PI-010",
        name="Privilege Escalation",
        description="Attempts to gain elevated permissions or access",
        severity=RuleSeverity.HIGH,
        pattern=re.compile(
            r"\b(sudo|root access|admin mode|administrator|superuser|"
            r"elevated privileges?|unrestricted access|full access|"
            r"disable (safety|filter|restriction|guardrail)s?)\b",
            re.IGNORECASE,
        ),
    ),

    # --- Data exfiltration commands ---
    Rule(
        id="PI-011",
        name="Exfiltration Command",
        description="Instructions to send data to external locations",
        severity=RuleSeverity.CRITICAL,
        pattern=re.compile(
            r"\b(send|transmit|upload|post|forward|email|relay|exfiltrate)\b"
            r".{0,60}\b(to|via)\b.{0,60}"
            r"(https?://|ftp://|smtp://|webhook|endpoint|server|url|api)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # --- Completion / end-of-task manipulation ---
    Rule(
        id="PI-012",
        name="Task Completion Hijack",
        description="Injected content pretending the task is done to redirect behavior",
        severity=RuleSeverity.MEDIUM,
        pattern=re.compile(
            r"\b(task (complete|done|finished|accomplished)|"
            r"you have (successfully|now)|mission accomplished|"
            r"proceed to (the next|your next|step))\b",
            re.IGNORECASE,
        ),
    ),

    # --- Encoding / obfuscation ---
    Rule(
        id="PI-013",
        name="Encoded Payload",
        description="Base64 or other encoded content that may contain hidden instructions",
        severity=RuleSeverity.MEDIUM,
        pattern=re.compile(
            r"\b(decode|base64|rot13|hex decode|url decode|eval|exec)\s*[\(:\"']",
            re.IGNORECASE,
        ),
    ),

    # --- Prompt leakage via translation ---
    Rule(
        id="PI-014",
        name="Language Switch Attack",
        description="Switches language to bypass content filters",
        severity=RuleSeverity.LOW,
        pattern=re.compile(
            r"\b(translate (this )?to|in (french|spanish|german|chinese|arabic|russian|japanese))\b"
            r".{0,80}\b(ignore|bypass|forbidden|restricted|not allowed)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # --- Virtualization / simulation framing ---
    Rule(
        id="PI-015",
        name="Simulation Framing",
        description="Frames malicious instructions as hypothetical or simulated",
        severity=RuleSeverity.MEDIUM,
        pattern=re.compile(
            r"\b(hypothetically|theoretically|for (educational|research|training) purposes?|"
            r"in a (simulation|fictional|story|game|scenario)|"
            r"imagine (you are|that you|if you)|"
            r"as a (thought experiment|exercise|test))\b",
            re.IGNORECASE,
        ),
    ),
]


class RuleEngine:
    """
    Rule-based detection engine.

    Applies all enabled rules to input text and returns a list of matches.
    Rules can be added, removed, or toggled at runtime.
    """

    def __init__(self, custom_rules: Optional[List[Rule]] = None) -> None:
        self._rules: List[Rule] = list(_BUILTIN_RULES)
        if custom_rules:
            self._rules.extend(custom_rules)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule to the engine."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found and removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID without removing it."""
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = False
                return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Re-enable a previously disabled rule."""
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = True
                return True
        return False

    def scan(self, text: str) -> List[RuleMatch]:
        """
        Scan text against all enabled rules.

        Returns a list of RuleMatch objects for each triggered rule.
        """
        matches: List[RuleMatch] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            if rule.pattern:
                for m in rule.pattern.finditer(text):
                    matches.append(
                        RuleMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            matched_text=m.group(),
                            start=m.start(),
                            end=m.end(),
                            description=rule.description,
                        )
                    )
            elif rule.keywords:
                for kw in rule.keywords:
                    # Use word-boundary regex for accurate keyword matching
                    kw_pattern = re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
                    m = kw_pattern.search(text)
                    if m:
                        matches.append(
                            RuleMatch(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                matched_text=m.group(),
                                start=m.start(),
                                end=m.end(),
                                description=rule.description,
                            )
                        )
                        break  # one match per keyword rule is enough

        return matches

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    @property
    def active_rule_count(self) -> int:
        return sum(1 for r in self._rules if r.enabled)
