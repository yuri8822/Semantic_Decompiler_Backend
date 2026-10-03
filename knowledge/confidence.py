"""
Confidence gating — what a discovery's confidence allows:

  HIGH     applied automatically (Ghidra + C++)
  MEDIUM   applied, but marked TODO so a human can find it
  LOW      not applied; the function is queued for another analysis pass

This is what stops one bad guess from poisoning the whole reconstruction.
"""

from config import CONFIDENCE_HIGH, CONFIDENCE_MEDIUM

HIGH, MEDIUM, LOW = "high", "medium", "low"


def tier(confidence: float) -> str:
    if confidence >= CONFIDENCE_HIGH:
        return HIGH
    if confidence >= CONFIDENCE_MEDIUM:
        return MEDIUM
    return LOW


def accepted(confidence: float) -> bool:
    """High or medium: safe to apply."""
    return confidence >= CONFIDENCE_MEDIUM


def needs_todo(confidence: float) -> bool:
    return CONFIDENCE_MEDIUM <= confidence < CONFIDENCE_HIGH


def todo(what: str, confidence: float) -> str:
    return f"TODO: {what} is a medium-confidence guess ({confidence:.2f})"


def analysis_needs_another_pass(analysis) -> bool:
    """
    LOW-confidence results worth revisiting once the improved decompilation
    (with neighbours renamed and types applied) is available.
    """
    if analysis is None:
        return True
    if not accepted(analysis.name_confidence) or analysis.contradictions:
        return True
    normal_params = [p for p in analysis.params if p.role == "normal"]
    if normal_params and sum(not accepted(p.confidence) for p in normal_params) * 2 > len(normal_params):
        return True
    return False
