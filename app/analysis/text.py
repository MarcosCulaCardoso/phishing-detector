import html
import re

from app.analysis import rules
from app.analysis.models import RuleHit, assessed
from app.parsing.models import ParsedEmail
from app.schemas import Modality

SOURCE = "text_rules"

URGENCY_PHRASES = (
    "urgent", "act now", "final notice", "within 24 hours", "in 24 hours",
    "suspended", "will be closed", "verify now", "unusual activity",
)
CREDENTIAL_PHRASES = (
    "confirm your password", "verify your password", "enter your password",
    "verify your account", "confirm your account", "login details",
    "update your payment", "payment details", "billing information",
    "bank details", "credit card", "gift card", "wire transfer",
)
MAX_QUOTED = 3


def _phrase_re(phrases: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(re.escape(p) for p in phrases) + r")\b", re.IGNORECASE)


_URGENCY_RE = _phrase_re(URGENCY_PHRASES)
_CREDENTIAL_RE = _phrase_re(CREDENTIAL_PHRASES)


def _readable_text(email: ParsedEmail) -> str:
    body = email.text_body
    if not body.strip():
        # HTML-only email: strip tags to get the words. The HTML is never rendered.
        body = html.unescape(re.sub(r"<[^>]+>", " ", email.html_body))
    return " ".join(f"{email.subject}\n{body}".split())


def _matches(pattern: re.Pattern[str], text: str) -> list[str]:
    found = dict.fromkeys(m.group(0).lower() for m in pattern.finditer(text))
    return list(found)[:MAX_QUOTED]


def check_text(email: ParsedEmail) -> list[RuleHit]:
    """Keyword checks. These are judgments about wording, so always ASSESSMENT."""
    text = _readable_text(email)
    hits: list[RuleHit] = []

    if phrases := _matches(_CREDENTIAL_RE, text):
        hits.append(RuleHit(rule="credential_request", points=rules.CREDENTIAL_REQUEST, evidence=[
            assessed(Modality.TEXT, f"Wording asks for credentials or payment "
                     f"(matched: {', '.join(repr(p) for p in phrases)})", SOURCE),
        ]))
    if phrases := _matches(_URGENCY_RE, text):
        hits.append(RuleHit(rule="urgency", points=rules.URGENCY, evidence=[
            assessed(Modality.TEXT, f"Wording creates urgency or threat "
                     f"(matched: {', '.join(repr(p) for p in phrases)})", SOURCE),
        ]))
    return hits
