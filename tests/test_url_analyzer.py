from app.schemas import EvidenceKind
from app.urls.analyzer import analyze_url


def kinds(analysis):
    return {e.kind for e in analysis.evidence}


def test_leetspeak_lookalike_flagged():
    a = analyze_url("http://micros0ft-support.example/login")
    assert a.features.brand_impersonated == "microsoft"
    assert a.features.impersonation_type == "lookalike characters"
    assert EvidenceKind.ASSESSMENT in kinds(a)


def test_legitimate_brand_domain_not_flagged():
    a = analyze_url("https://www.microsoft.com/account")
    assert a.features.registered_domain == "microsoft.com"
    assert a.features.brand_impersonated is None
    assert a.evidence == []


def test_brand_in_subdomain_flagged():
    a = analyze_url("https://paypal.com.secure-login.example/")
    assert a.features.brand_impersonated == "paypal"
    assert a.features.impersonation_type == "brand name in subdomain"
    assert a.features.registered_domain == "secure-login.example"


def test_ip_host_detected():
    a = analyze_url("http://192.0.2.10/login")
    assert a.features.is_ip_host is True


def test_obfuscated_integer_ip_detected():
    a = analyze_url("http://3232235777/")
    assert a.features.is_ip_host is True


def test_userinfo_trick_detected():
    a = analyze_url("http://www.paypal.com@evil.example/")
    assert a.features.has_userinfo is True
    assert a.features.host == "evil.example"


def test_punycode_homograph_detected():
    a = analyze_url("http://xn--pple-43d.example/")
    assert a.features.is_idn is True
    assert a.features.host_unicode != a.features.host
    assert a.features.brand_impersonated == "apple"


def test_mixed_script_detected():
    a = analyze_url("http://p\u0430ypal.example/")
    assert a.features.has_mixed_script is True
    assert a.features.brand_impersonated == "paypal"


def test_anchor_mismatch_flagged():
    a = analyze_url(
        "http://micros0ft-support.example/login?id=1",
        "https://www.microsoft.com/account",
    )
    assert a.features.anchor_mismatch is True
    assert a.features.anchor_domain == "microsoft.com"
    assert any("microsoft.com" in e.statement for e in a.evidence)


def test_anchor_match_not_flagged():
    a = analyze_url("https://www.microsoft.com/x", "microsoft.com")
    assert a.features.anchor_mismatch is False


def test_same_brand_codomain_not_flagged():
    a = analyze_url("https://login.microsoftonline.com/x", "microsoft.com")
    assert a.features.anchor_mismatch is False


def test_shortener_detected():
    a = analyze_url("https://bit.ly/abc")
    assert a.features.is_shortener is True


def test_javascript_scheme_flagged():
    a = analyze_url("javascript:alert(1)")
    assert a.features.scheme == "javascript"
    assert a.features.host == ""
    assert EvidenceKind.ASSESSMENT in kinds(a)


def test_unparseable_url_returns_none():
    assert analyze_url("http://[invalid") is None


def test_near_match_typosquat_detected():
    for url in ("https://paypall.example/", "https://microsft.example/"):
        a = analyze_url(url)
        assert a.features.brand_impersonated is not None
        assert a.features.impersonation_type == "near-match typosquat"


def test_common_words_not_flagged():
    for url in ("https://purchase.example/", "https://phase.example/", "https://example.org/"):
        assert analyze_url(url).features.brand_impersonated is None


def test_nonstandard_port_detected():
    a = analyze_url("http://example.test:8080/")
    assert a.features.has_nonstandard_port is True
