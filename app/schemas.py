from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


class Action(str, Enum):
    DELIVER = "deliver"
    WARN = "warn"
    QUARANTINE = "quarantine"


class Modality(str, Enum):
    SENDER = "sender"
    TEXT = "text"
    URL = "url"
    HTML = "html"
    SCREENSHOT = "screenshot"
    ATTACHMENT = "attachment"


class EvidenceKind(str, Enum):
    OBSERVED = "observed"      # a fact extracted deterministically from the email
    ASSESSMENT = "assessment"  # a judgment made by a model or heuristic


class Evidence(BaseModel):
    kind: EvidenceKind
    modality: Modality
    statement: str
    source: str = Field(description="Component that produced this, e.g. 'url_analyzer'")


class SecurityReport(BaseModel):
    verdict: Verdict
    # None means there is no calibrated probability (e.g. rule-based scoring).
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    risk_indicators: list[Evidence] = Field(default_factory=list)
    benign_indicators: list[Evidence] = Field(default_factory=list)
    reasoning: str
    recommended_action: Action

    def render(self) -> str:
        lines = [f"Classification: {self.verdict.value.upper()}"]
        if self.confidence is not None:
            lines.append(f"Confidence: {self.confidence:.0%}")
            lines.append(f"Risk score: {self.risk_score}/100")
        else:
            lines.append(f"Risk score: {self.risk_score}/100 (rule-based, not calibrated)")
        lines += ["", "Risk indicators:"]
        for ev in self.risk_indicators:
            lines.append(f"  [{ev.kind.value}] ({ev.modality.value}) {ev.statement}")
        lines += ["", f"Reasoning: {self.reasoning}"]
        lines.append(f"Recommended action: {self.recommended_action.value}")
        return "\n".join(lines)
