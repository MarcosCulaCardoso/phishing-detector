from app.analysis import rules
from app.analysis.attachments import check_attachments
from app.analysis.links import check_links
from app.analysis.sender import check_sender
from app.analysis.text import check_text
from app.parsing.models import Address, AttachmentInfo, ParsedEmail
from app.schemas import EvidenceKind


def rule_names(hits):
    return {hit.rule for hit in hits}


def attachment(filename: str) -> AttachmentInfo:
    return AttachmentInfo(filename=filename, content_type="application/octet-stream",
                          size_bytes=1, sha256="0" * 64)


# --- sender ---

def test_reply_to_mismatch_fires():
    email = ParsedEmail(sender=Address(email="a@shop.example"),
                        reply_to=[Address(email="b@other.example")])
    assert "reply_to_mismatch" in rule_names(check_sender(email))


def test_reply_to_subdomain_of_sender_is_fine():
    email = ParsedEmail(sender=Address(email="a@shop.example"),
                        reply_to=[Address(email="b@help.shop.example")])
    assert check_sender(email) == []


def test_display_name_brand_fires_for_wrong_domain():
    email = ParsedEmail(sender=Address(display_name="PayPal Support", email="x@pay-help.example"))
    assert "display_name_brand" in rule_names(check_sender(email))


def test_display_name_brand_ok_for_real_domain():
    email = ParsedEmail(sender=Address(display_name="PayPal", email="service@mail.paypal.com"))
    assert check_sender(email) == []


def test_display_name_multiword_brand():
    email = ParsedEmail(sender=Address(display_name="Bank of America Alerts", email="x@boa-alerts.example"))
    assert "display_name_brand" in rule_names(check_sender(email))


def test_spf_and_dkim_failures_are_observed():
    email = ParsedEmail(authentication_results=["mx.test.example; spf=softfail; dkim=fail"])
    hits = check_sender(email)
    assert rule_names(hits) == {"spf_fail", "dkim_fail"}
    assert all(ev.kind == EvidenceKind.OBSERVED for hit in hits for ev in hit.evidence)


def test_auth_pass_and_none_do_not_fire():
    email = ParsedEmail(authentication_results=["mx.test.example; spf=pass; dkim=none"])
    assert check_sender(email) == []


# --- attachments ---

def test_double_extension_scores_once_not_twice():
    hits = check_attachments(ParsedEmail(attachments=[attachment("invoice.pdf.exe")]))
    assert rule_names(hits) == {"double_extension"}
    assert hits[0].points == rules.DOUBLE_EXTENSION


def test_double_extension_with_trailing_dot_and_caps():
    hits = check_attachments(ParsedEmail(attachments=[attachment("INVOICE.PDF.EXE. ")]))
    assert rule_names(hits) == {"double_extension"}


def test_risky_extensions_fire():
    for name in ("setup.exe", "photo.scr", "run.js", "disk.iso", "shortcut.lnk"):
        hits = check_attachments(ParsedEmail(attachments=[attachment(name)]))
        assert rule_names(hits) == {"risky_extension"}, name


def test_safe_attachments_and_missing_names_ignored():
    email = ParsedEmail(attachments=[attachment("receipt.pdf"), attachment(None)])
    assert check_attachments(email) == []


# --- text ---

def test_credential_request_is_assessment_only():
    hits = check_text(ParsedEmail(text_body="Please confirm your password to continue."))
    assert rule_names(hits) == {"credential_request"}
    assert all(ev.kind == EvidenceKind.ASSESSMENT for ev in hits[0].evidence)


def test_urgency_detected_in_subject():
    hits = check_text(ParsedEmail(subject="URGENT: action needed"))
    assert rule_names(hits) == {"urgency"}
    assert hits[0].evidence[0].kind == EvidenceKind.ASSESSMENT


def test_html_only_body_is_checked():
    email = ParsedEmail(html_body="<p>Update your <b>payment details</b> today</p>")
    assert "credential_request" in rule_names(check_text(email))


def test_ordinary_text_does_not_fire():
    assert check_text(ParsedEmail(subject="Lunch?", text_body="See you at noon.")) == []


# --- links ---

def test_dangerous_scheme_fires():
    email = ParsedEmail(links=[{"href": "javascript:alert(1)", "anchor_text": "click"}])
    assert "dangerous_scheme" in rule_names(check_links(email))


def test_ip_host_fires():
    email = ParsedEmail(text_body="Go to https://192.0.2.10/login")
    assert "ip_host" in rule_names(check_links(email))


def test_repeated_bad_link_counts_once():
    email = ParsedEmail(text_body=" ".join(f"http://192.0.2.10/{i}" for i in range(5)))
    hits = check_links(email)
    assert [hit.rule for hit in hits].count("ip_host") == 1
    assert [hit.rule for hit in hits].count("plain_http") == 1


def test_clean_https_link_does_not_fire():
    assert check_links(ParsedEmail(text_body="https://shop.example/orders")) == []
