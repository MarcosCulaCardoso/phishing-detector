import pytest
from pydantic import ValidationError

from app.schemas import Action, SecurityReport, Verdict


def make_report(**overrides) -> SecurityReport:
    data = dict(
        verdict=Verdict.SUSPICIOUS,
        confidence=0.6,
        risk_score=55,
        reasoning="test",
        recommended_action=Action.WARN,
    )
    data.update(overrides)
    return SecurityReport(**data)


def test_valid_report_renders():
    text = make_report().render()
    assert "Classification: SUSPICIOUS" in text
    assert "Confidence: 60%" in text


def test_report_with_confidence_renders_exactly_as_before():
    expected = "\n".join([
        "Classification: SUSPICIOUS",
        "Confidence: 60%",
        "Risk score: 55/100",
        "",
        "Risk indicators:",
        "",
        "Reasoning: test",
        "Recommended action: warn",
    ])
    assert make_report().render() == expected


def test_report_without_confidence_is_valid_and_labels_score():
    text = make_report(confidence=None).render()
    assert "Confidence" not in text
    assert "Risk score: 55/100 (rule-based, not calibrated)" in text


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        make_report(confidence=1.5)
    with pytest.raises(ValidationError):
        make_report(confidence=-0.1)


def test_unknown_verdict_rejected():
    with pytest.raises(ValidationError):
        make_report(verdict="maybe")
