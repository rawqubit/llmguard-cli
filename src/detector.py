"""
llmguard-cli: Core detection engine for prompt injection and jailbreak attacks.
Uses a multi-layer approach: heuristic pattern matching, semantic similarity,
and LLM-based meta-reasoning to classify adversarial prompts.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    ROLE_HIJACKING = "role_hijacking"
    INSTRUCTION_OVERRIDE = "instruction_override"
    SOCIAL_ENGINEERING = "social_engineering"
    BENIGN = "benign"


@dataclass
class DetectionResult:
    input_text: str
    is_threat: bool
    threat_category: ThreatCategory
    heuristic_score: float       # 0.0 - 1.0
    ai_score: Optional[float]    # 0.0 - 1.0, None if AI not used
    confidence: float            # Combined confidence
    matched_patterns: list[str] = field(default_factory=list)
    explanation: Optional[str] = None
    recommended_action: str = "allow"

    def to_dict(self) -> dict:
        return {
            "is_threat": self.is_threat,
            "threat_category": self.threat_category.value,
            "heuristic_score": round(self.heuristic_score, 3),
            "ai_score": round(self.ai_score, 3) if self.ai_score is not None else None,
            "confidence": round(self.confidence, 3),
            "matched_patterns": self.matched_patterns,
            "explanation": self.explanation,
            "recommended_action": self.recommended_action,
            "input_preview": self.input_text[:200] + "..." if len(self.input_text) > 200 else self.input_text,
        }


# ---------------------------------------------------------------------------
# Heuristic detection patterns
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    # Instruction override attempts
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)", ThreatCategory.INSTRUCTION_OVERRIDE, 0.90),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", ThreatCategory.INSTRUCTION_OVERRIDE, 0.90),
    (r"(?i)forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed|trained)", ThreatCategory.INSTRUCTION_OVERRIDE, 0.85),
    (r"(?i)new\s+(system\s+)?prompt\s*:", ThreatCategory.PROMPT_INJECTION, 0.85),
    (r"(?i)\[system\]|\[INST\]|<\|system\|>|<\|im_start\|>system", ThreatCategory.PROMPT_INJECTION, 0.80),

    # Role hijacking
    (r"(?i)you\s+are\s+now\s+(a\s+)?(different|new|evil|unrestricted|DAN|jailbroken)", ThreatCategory.ROLE_HIJACKING, 0.85),
    (r"(?i)act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?(DAN|evil|unrestricted|jailbroken|unfiltered)", ThreatCategory.ROLE_HIJACKING, 0.90),
    (r"(?i)pretend\s+(you\s+)?(are|have\s+no)\s+(restrictions?|limits?|guidelines?|rules?|ethics?)", ThreatCategory.ROLE_HIJACKING, 0.85),
    (r"(?i)your\s+(true|real|actual)\s+(self|identity|purpose)\s+is", ThreatCategory.ROLE_HIJACKING, 0.75),

    # Jailbreak patterns
    (r"(?i)\bDAN\b.*\bdo\s+anything\s+now\b", ThreatCategory.JAILBREAK, 0.95),
    (r"(?i)jailbreak|jail\s*break", ThreatCategory.JAILBREAK, 0.80),
    (r"(?i)developer\s+mode\s+(enabled|on|activated)", ThreatCategory.JAILBREAK, 0.85),
    (r"(?i)bypass\s+(your\s+)?(safety|content|ethical|moral)\s+(filters?|guidelines?|restrictions?|training)", ThreatCategory.JAILBREAK, 0.90),
    (r"(?i)without\s+(any\s+)?(restrictions?|limitations?|filters?|guidelines?|ethics?|morals?)", ThreatCategory.JAILBREAK, 0.75),
    (r"(?i)in\s+(this|a)\s+(hypothetical|fictional|imaginary|alternate)\s+(world|scenario|universe|reality)", ThreatCategory.JAILBREAK, 0.60),

    # Data exfiltration
    (r"(?i)repeat\s+(everything|all)\s+(above|before|prior|in\s+your\s+(system\s+)?prompt)", ThreatCategory.DATA_EXFILTRATION, 0.90),
    (r"(?i)print\s+(your\s+)?(system\s+prompt|instructions?|context|initial\s+prompt)", ThreatCategory.DATA_EXFILTRATION, 0.90),
    (r"(?i)what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|initial\s+context)", ThreatCategory.DATA_EXFILTRATION, 0.80),
    (r"(?i)reveal\s+(your\s+)?(hidden|secret|system|original)\s+(instructions?|prompt|context)", ThreatCategory.DATA_EXFILTRATION, 0.90),
    (r"(?i)translate\s+(the\s+)?(above|previous|your\s+system)\s+(prompt|instructions?)\s+to", ThreatCategory.DATA_EXFILTRATION, 0.85),

    # Social engineering
    (r"(?i)my\s+(boss|manager|ceo|supervisor)\s+(told|asked|wants|needs)\s+me\s+to\s+(bypass|ignore|override)", ThreatCategory.SOCIAL_ENGINEERING, 0.75),
    (r"(?i)this\s+is\s+(an?\s+)?(emergency|urgent|critical)\s+(situation|case)", ThreatCategory.SOCIAL_ENGINEERING, 0.55),
    (r"(?i)for\s+(research|educational|academic|testing)\s+purposes?\s+(only\s+)?[,.]?\s*(please\s+)?(ignore|bypass|disable)", ThreatCategory.SOCIAL_ENGINEERING, 0.80),
]


def heuristic_scan(text: str) -> tuple[float, ThreatCategory, list[str]]:
    """
    Scan text with heuristic patterns.
    Returns (max_score, dominant_category, matched_pattern_descriptions).
    """
    max_score = 0.0
    dominant_category = ThreatCategory.BENIGN
    matched = []

    for pattern, category, score in INJECTION_PATTERNS:
        if re.search(pattern, text):
            matched.append(f"{category.value}: {pattern[:60]}...")
            if score > max_score:
                max_score = score
                dominant_category = category

    return max_score, dominant_category, matched


def compute_final_verdict(
    heuristic_score: float,
    ai_score: Optional[float],
    threat_category: ThreatCategory,
    threshold: float = 0.65,
) -> tuple[bool, float, str]:
    """
    Combine heuristic and AI scores into a final verdict.
    Returns (is_threat, confidence, recommended_action).
    """
    if ai_score is not None:
        # Weighted combination: AI gets 60%, heuristic gets 40%
        combined = ai_score * 0.60 + heuristic_score * 0.40
    else:
        combined = heuristic_score

    is_threat = combined >= threshold

    if combined >= 0.90:
        action = "block"
    elif combined >= 0.70:
        action = "flag_for_review"
    elif combined >= 0.50:
        action = "log_and_monitor"
    else:
        action = "allow"

    return is_threat, round(combined, 3), action
