from app.analysis import rules
from app.analysis.models import RuleHit, assessed, observed
from app.parsing.models import ParsedEmail
from app.schemas import Modality

SOURCE = "attachment_rules"

RISKY_EXTENSIONS = {"exe", "scr", "js", "iso", "lnk"}
# Harmless-looking extensions attackers put in front of a risky one.
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png", "zip"}


def _extensions(filename: str) -> list[str]:
    # Windows ignores trailing dots and spaces, so "a.exe. " still runs as .exe
    parts = filename.lower().rstrip(" .").split(".")
    return parts[1:]


def check_attachments(email: ParsedEmail) -> list[RuleHit]:
    """Judges file names only. Attachment contents are never opened."""
    double: list[str] = []
    risky: list[str] = []
    for att in email.attachments:
        exts = _extensions(att.filename or "")
        if not exts or exts[-1] not in RISKY_EXTENSIONS:
            continue
        if len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS:
            double.append(att.filename or "")
        else:
            risky.append(att.filename or "")

    # repr() escapes control characters an attacker might put in a file name.
    if double:
        return [RuleHit(rule="double_extension", points=rules.DOUBLE_EXTENSION, evidence=[
            *(observed(Modality.ATTACHMENT, f"Attachment {name!r} has a double extension", SOURCE)
              for name in double),
            assessed(Modality.ATTACHMENT, "A program disguised as a document is a common "
                     "malware delivery trick", SOURCE),
        ])]
    if risky:
        return [RuleHit(rule="risky_extension", points=rules.RISKY_EXTENSION, evidence=[
            *(observed(Modality.ATTACHMENT, f"Attachment {name!r} is a file type that can run code",
                       SOURCE) for name in risky),
        ])]
    return []
