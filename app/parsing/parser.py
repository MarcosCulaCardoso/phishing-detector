import hashlib
import logging
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses

from app.parsing.html_links import extract_links
from app.parsing.models import Address, AttachmentInfo, ParsedEmail

log = logging.getLogger(__name__)

MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_BODY_CHARS = 200_000


def _header(msg: EmailMessage, name: str) -> str | None:
    value = msg.get(name)
    return None if value is None else str(value)


def _addresses(msg: EmailMessage, name: str) -> list[Address]:
    values = [str(v) for v in msg.get_all(name, [])]
    return [
        Address(display_name=display, email=addr.strip().lower())
        for display, addr in getaddresses(values)
    ]


def _body(msg: EmailMessage, kind: str) -> str:
    part = msg.get_body(preferencelist=(kind,))
    if part is None:
        return ""
    try:
        content = part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace")
    return str(content)[:MAX_BODY_CHARS]


def _attachments(msg: EmailMessage) -> list[AttachmentInfo]:
    found: list[AttachmentInfo] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() != "attachment" and part.get_filename() is None:
            continue
        payload = part.get_payload(decode=True) or b""
        found.append(
            AttachmentInfo(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return found


def parse_eml_bytes(raw: bytes) -> ParsedEmail:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError(f"Email exceeds {MAX_EMAIL_BYTES} bytes")

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    senders = _addresses(msg, "From")
    html_body = _body(msg, "html")

    parsed = ParsedEmail(
        subject=_header(msg, "Subject") or "",
        sender=senders[0] if senders else Address(),
        reply_to=_addresses(msg, "Reply-To"),
        to=_addresses(msg, "To"),
        return_path=_header(msg, "Return-Path"),
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        authentication_results=[str(v) for v in msg.get_all("Authentication-Results", [])],
        text_body=_body(msg, "plain"),
        html_body=html_body,
        links=extract_links(html_body),
        attachments=_attachments(msg),
    )
    log.info(
        "Parsed email: %d links, %d attachments",
        len(parsed.links),
        len(parsed.attachments),
    )
    return parsed
