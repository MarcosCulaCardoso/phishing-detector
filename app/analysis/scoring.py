import logging

from app.analysis import rules
from app.analysis.attachments import check_attachments
from app.analysis.links import check_links
from app.analysis.models import AnalysisResult
from app.analysis.sender import check_sender
from app.analysis.text import check_text
from app.parsing.models import ParsedEmail
from app.schemas import Action, SecurityReport, Verdict

log = logging.getLogger(__name__)

ACTIONS = {
    Verdict.LEGITIMATE: Action.DELIVER,
    Verdict.SUSPICIOUS: Action.WARN,
    Verdict.PHISHING: Action.QUARANTINE,
}


def verdict_for(score: int) -> Verdict:
    if score >= rules.PHISHING_THRESHOLD:
        return Verdict.PHISHING
    if score >= rules.SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.LEGITIMATE


def analyze_email(email: ParsedEmail) -> AnalysisResult:
    hits = [*check_sender(email), *check_links(email), *check_attachments(email), *check_text(email)]
    raw = sum(hit.points for hit in hits)
    score = min(raw, rules.MAX_SCORE)
    verdict = verdict_for(score)

    if hits:
        reasoning = f"{len(hits)} rule(s) fired for {raw} points"
        if raw > score:
            reasoning += f", capped at {rules.MAX_SCORE}"
    else:
        reasoning = "No rules fired"
    reasoning += (f". Rule-based thresholds: suspicious >= {rules.SUSPICIOUS_THRESHOLD}, "
                  f"phishing >= {rules.PHISHING_THRESHOLD}.")

    report = SecurityReport(
        verdict=verdict,
        confidence=None,  # rule-based score, not a calibrated probability
        risk_score=score,
        risk_indicators=[ev for hit in hits for ev in hit.evidence],
        reasoning=reasoning,
        recommended_action=ACTIONS[verdict],
    )
    log.info("Rule-based analysis: %d rule(s) fired, score %d, verdict %s",
             len(hits), score, verdict.value)
    return AnalysisResult(hits=hits, raw_score=raw, report=report)
