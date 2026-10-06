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


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        make_report(confidence=1.5)


def test_unknown_verdict_rejected():
    with pytest.raises(ValidationError):
        make_report(verdict="maybe")
