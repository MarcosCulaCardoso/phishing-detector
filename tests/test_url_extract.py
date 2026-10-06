from pathlib import Path

from app.parsing.models import ParsedEmail
from app.parsing.parser import parse_eml_bytes
from app.urls.extract import MAX_URLS, extract_urls

FIXTURES = Path(__file__).parent / "fixtures"


def test_extracts_html_and_text_urls_from_fixture():
    email = parse_eml_bytes((FIXTURES / "phishing_sample.eml").read_bytes())
    targets = extract_urls(email)
    assert len(targets) == 2
    html_target = next(t for t in targets if t.origin == "html")
    assert html_target.anchor_text == "https://www.microsoft.com/account"


def test_trailing_punctuation_stripped():
    email = ParsedEmail(text_body="Go to https://a.example/x, then (https://b.example/y). Done!")
    hrefs = [t.href for t in extract_urls(email)]
    assert hrefs == ["https://a.example/x", "https://b.example/y"]


def test_duplicates_removed_and_html_anchor_kept():
    email = ParsedEmail(
        text_body="https://a.example/x",
        links=[{"href": "https://a.example/x", "anchor_text": "click"}],
    )
    targets = extract_urls(email)
    assert len(targets) == 1
    assert targets[0].anchor_text == "click"


def test_url_cap_enforced():
    body = " ".join(f"https://site{i}.example/" for i in range(MAX_URLS + 30))
    assert len(extract_urls(ParsedEmail(text_body=body))) == MAX_URLS
