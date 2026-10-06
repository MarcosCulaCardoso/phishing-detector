from app.analysis import rules
from app.analysis.models import AnalysisResult
from app.schemas import Evidence, EvidenceKind


def _printable(text: str) -> str:
    """Replace control characters so attacker text can't mess with the terminal."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _section(title: str, items: list[Evidence]) -> list[str]:
    lines = [f"{title}:"]
    lines += [f"  - ({ev.modality.value}) {_printable(ev.statement)}" for ev in items] or ["  (none)"]
    return lines


def render_analysis(result: AnalysisResult) -> str:
    report = result.report
    evidence = report.risk_indicators
    lines = [
        f"Classification: {report.verdict.value.upper()}",
        f"Risk score: {report.risk_score}/100 (rule-based, not calibrated)",
        f"Recommended action: {report.recommended_action.value}",
        "",
        *_section("Observed facts", [e for e in evidence if e.kind == EvidenceKind.OBSERVED]),
        "",
        *_section("Assessments", [e for e in evidence if e.kind == EvidenceKind.ASSESSMENT]),
        "",
        "Score breakdown:",
    ]
    lines += [f"  +{hit.points:<3} {hit.rule}" for hit in result.hits] or ["  (no rules fired)"]
    total = f"  = {result.raw_score}"
    if result.raw_score > report.risk_score:
        total += f" (capped at {rules.MAX_SCORE})"
    lines += [
        total,
        f"Thresholds: suspicious >= {rules.SUSPICIOUS_THRESHOLD}, "
        f"phishing >= {rules.PHISHING_THRESHOLD}",
    ]
    return "\n".join(lines)
