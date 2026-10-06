from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analysis import rules
from app.analysis.__main__ import main
from app.analysis.models import RuleHit
from app.analysis.scoring import analyze_email, verdict_for
from app.parsing.models import ParsedEmail
from app.parsing.parser import parse_eml_bytes
from app.schemas import Action, Verdict

FIXTURES = Path(__file__).parent / "fixtures"


def analyze_fixture(name: str):
    return analyze_email(parse_eml_bytes((FIXTURES / name).read_bytes()))


def test_phishing_sample_scores_phishing():
    result = analyze_fixture("phishing_sample.eml")
    assert result.report.verdict == Verdict.PHISHING
    assert result.report.recommended_action == Action.QUARANTINE


def test_benign_sample_scores_legitimate():
    result = analyze_fixture("benign_sample.eml")
    assert result.report.verdict == Verdict.LEGITIMATE
    assert result.report.risk_score == 0
    assert result.hits == []


def test_score_is_capped_sum_of_rule_points():
    result = analyze_fixture("phishing_sample.eml")
    assert result.raw_score == sum(hit.points for hit in result.hits)
    assert result.report.risk_score == min(result.raw_score, rules.MAX_SCORE)


def test_every_evidence_in_report_comes_from_a_rule():
    result = analyze_fixture("phishing_sample.eml")
    from_hits = [ev for hit in result.hits for ev in hit.evidence]
    assert result.report.risk_indicators == from_hits


def test_rule_hit_without_evidence_rejected():
    with pytest.raises(ValidationError):
        RuleHit(rule="x", points=10, evidence=[])


def test_report_has_no_confidence():
    assert analyze_fixture("phishing_sample.eml").report.confidence is None


@pytest.mark.parametrize("score, verdict", [
    (0, Verdict.LEGITIMATE),
    (rules.SUSPICIOUS_THRESHOLD - 1, Verdict.LEGITIMATE),
    (rules.SUSPICIOUS_THRESHOLD, Verdict.SUSPICIOUS),
    (rules.PHISHING_THRESHOLD - 1, Verdict.SUSPICIOUS),
    (rules.PHISHING_THRESHOLD, Verdict.PHISHING),
])
def test_threshold_boundaries(score, verdict):
    assert verdict_for(score) == verdict


def test_empty_email_does_not_crash():
    result = analyze_email(ParsedEmail())
    assert result.report.verdict == Verdict.LEGITIMATE


def test_garbage_email_does_not_crash():
    result = analyze_email(parse_eml_bytes(b"this is not an email"))
    assert result.report.verdict == Verdict.LEGITIMATE


def test_cli_output_is_labeled_and_defanged(capsys):
    assert main(["prog", str(FIXTURES / "phishing_sample.eml")]) == 0
    out = capsys.readouterr().out
    assert "Classification: PHISHING" in out
    assert "rule-based, not calibrated" in out
    assert "Confidence" not in out
    assert "Observed facts:" in out and "Assessments:" in out
    assert "http://" not in out and "https://" not in out
    assert "micros0ft-support.example" not in out
    assert "micros0ft-support[.]example" in out


def test_cli_bad_usage_and_missing_file(tmp_path):
    assert main(["prog"]) == 2
    assert main(["prog", str(tmp_path / "missing.eml")]) == 1
