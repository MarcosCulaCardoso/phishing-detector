from collections.abc import Callable

from app.analysis import rules
from app.analysis.models import RuleHit, assessed, observed
from app.parsing.models import ParsedEmail
from app.schemas import Evidence, Modality
from app.urls.analyzer import DANGEROUS_SCHEMES, analyze_url
from app.urls.extract import defang, extract_urls
from app.urls.models import UrlFeatures

SOURCE = "link_rules"
_URL = Modality.URL


def _obs(text: str) -> Evidence:
    return observed(_URL, text, SOURCE)


def _asm(text: str) -> Evidence:
    return assessed(_URL, text, SOURCE)


# (rule name, points, does it apply?, evidence to show). First matching link is described.
_LINK_RULES: list[tuple[str, int, Callable[[UrlFeatures], bool], Callable[[UrlFeatures], list[Evidence]]]] = [
    ("dangerous_scheme", rules.DANGEROUS_SCHEME,
     lambda f: f.scheme in DANGEROUS_SCHEMES,
     lambda f: [_obs(f"A link uses the '{f.scheme}:' scheme"),
                _asm("Script/data links can run code or hide content; no legitimate email needs one")]),
    ("anchor_mismatch", rules.ANCHOR_MISMATCH,
     lambda f: f.anchor_mismatch,
     lambda f: [_obs(f"Link text shows {defang(f.anchor_domain or '')} but the link goes to "
                     f"{defang(f.registered_domain)}"),
                _asm("Link text naming a different site than the real target is a strong deception signal")]),
    ("brand_lookalike", rules.BRAND_LOOKALIKE,
     lambda f: f.brand_impersonated is not None,
     lambda f: [_obs(f"Link goes to {defang(f.registered_domain)}, which is not a known "
                     f"{f.brand_impersonated} domain"),
                _asm(f"Domain appears to imitate {f.brand_impersonated} ({f.impersonation_type})")]),
    ("userinfo_trick", rules.USERINFO_TRICK,
     lambda f: f.has_userinfo,
     lambda f: [_obs(f"A link contains an '@' section; the real host is {defang(f.host)}"),
                _asm("Text before '@' is a known trick to make a link look like a trusted site")]),
    ("mixed_script", rules.MIXED_SCRIPT,
     lambda f: f.has_mixed_script,
     lambda f: [_obs("A link's domain mixes characters from different alphabets"),
                _asm("Mixed-alphabet domains are a classic homograph (lookalike character) attack")]),
    ("ip_host", rules.IP_HOST,
     lambda f: f.is_ip_host,
     lambda f: [_obs(f"A link points to a raw IP address ({defang(f.host)})"),
                _asm("Legitimate organizations almost never link to bare IP addresses")]),
    ("shortener", rules.SHORTENER,
     lambda f: f.is_shortener,
     lambda f: [_obs(f"A link uses the URL shortener {defang(f.registered_domain)}"),
                _asm("A shortener hides the real destination from the reader and from static analysis")]),
    ("plain_http", rules.PLAIN_HTTP,
     lambda f: f.scheme == "http",
     lambda f: [_obs("A link uses unencrypted HTTP")]),
    ("suspicious_tld", rules.SUSPICIOUS_TLD,
     lambda f: f.suspicious_tld,
     lambda f: [_obs(f"A link domain uses the .{f.suffix} ending"),
                _asm("This ending is frequently abused, but is a weak signal on its own")]),
    ("nonstandard_port", rules.NONSTANDARD_PORT,
     lambda f: f.has_nonstandard_port,
     lambda f: [_obs("A link uses a non-standard port")]),
]


def check_links(email: ParsedEmail) -> list[RuleHit]:
    features: list[UrlFeatures] = []
    for target in extract_urls(email):
        analysis = analyze_url(target.href, target.anchor_text)
        if analysis is not None:
            features.append(analysis.features)

    hits: list[RuleHit] = []
    for name, points, applies, describe in _LINK_RULES:
        match = next((f for f in features if applies(f)), None)
        if match is not None:
            hits.append(RuleHit(rule=name, points=points, evidence=describe(match)))
    return hits
