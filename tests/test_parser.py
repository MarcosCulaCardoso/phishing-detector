import hashlib
from pathlib import Path

import pytest

from app.parsing.parser import MAX_EMAIL_BYTES, parse_eml_bytes

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return parse_eml_bytes((FIXTURES / name).read_bytes())


def test_sender_fields():
    email = load("phishing_sample.eml")
    assert email.sender.display_name == "Microsoft Account Team"
    assert email.sender.email == "security@micros0ft-support.example"
    assert email.sender.domain == "micros0ft-support.example"


def test_reply_to_differs_from_sender():
    email = load("phishing_sample.eml")
    assert email.reply_to[0].domain == "collect-mail.example"
    assert email.reply_to[0].domain != email.sender.domain


def test_bodies_extracted():
    email = load("phishing_sample.eml")
    assert "suspended in 24 hours" in email.text_body
    assert "<a href" in email.html_body


def test_link_anchor_text_and_href_both_kept():
    email = load("phishing_sample.eml")
    assert len(email.links) == 1
    assert email.links[0].href.startswith("http://micros0ft-support.example")
    assert email.links[0].anchor_text == "https://www.microsoft.com/account"


def test_attachment_metadata_hashed_not_stored():
    email = load("phishing_sample.eml")
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "invoice.txt"
    assert att.size_bytes == 5
    assert att.sha256 == hashlib.sha256(b"hello").hexdigest()


def test_authentication_results_captured():
    email = load("phishing_sample.eml")
    assert "spf=fail" in email.authentication_results[0]


def test_oversized_input_rejected():
    with pytest.raises(ValueError):
        parse_eml_bytes(b"x" * (MAX_EMAIL_BYTES + 1))


def test_garbage_input_does_not_crash():
    email = parse_eml_bytes(b"this is not an email")
    assert email.subject == ""
    assert email.sender.email == ""
