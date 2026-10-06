import logging

from app.config import get_settings
from app.logging_config import setup_logging
from app.schemas import (
    Action,
    Evidence,
    EvidenceKind,
    Modality,
    SecurityReport,
    Verdict,
)


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    log = logging.getLogger(__name__)
    log.info("Starting demo with hard-coded placeholder data (not a real detection)")

    report = SecurityReport(
        verdict=Verdict.PHISHING,
        confidence=0.94,
        risk_score=91,
        risk_indicators=[
            Evidence(
                kind=EvidenceKind.OBSERVED,
                modality=Modality.URL,
                statement="Link host is 'micros0ft-login.example', displayed text says 'microsoft.com'",
                source="demo",
            ),
            Evidence(
                kind=EvidenceKind.ASSESSMENT,
                modality=Modality.TEXT,
                statement="Creates urgency around account suspension",
                source="demo",
            ),
        ],
        reasoning="Placeholder: shows the report format only.",
        recommended_action=Action.QUARANTINE,
    )
    print(report.render())


if __name__ == "__main__":
    main()
