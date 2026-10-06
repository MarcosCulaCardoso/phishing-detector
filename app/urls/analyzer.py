import ipaddress
import logging
import re
import unicodedata
from urllib.parse import urlsplit

import tldextract
from rapidfuzz.distance import Levenshtein

from app.schemas import Evidence, EvidenceKind, Modality
from app.urls.brands import BRANDS, CONFUSABLES, SHORTENERS, SUSPICIOUS_TLDS
from app.urls.models import UrlAnalysis, UrlFeatures

log = logging.getLogger(__name__)

SOURCE = "url_analyzer"
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript"}

# Static analysis only: use the bundled suffix list, never fetch anything.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_ANCHOR_RE = re.compile(
    r"(?<![@\w.-])(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[/:?#\s]|$)",
    re.IGNORECASE,
)


def _split_host(host: str) -> tuple[str, str, str, str]:
    """Return (subdomain, label, suffix, registered_domain) for a hostname.

    Uses the public suffix list when it recognizes the ending. For unknown or
    reserved endings (.example, .test, brand-new TLDs) it falls back to treating
    the last two labels as the registered domain, instead of the whole hostname.
    """
    ext = _TLD(host)
    if ext.suffix and ext.domain:
        return ext.subdomain, ext.domain, ext.suffix, f"{ext.domain}.{ext.suffix}"

    labels = [part for part in host.split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[:-2]), labels[-2], labels[-1], ".".join(labels[-2:])
    return "", host, "", host


def _host_unicode(host: str) -> str:
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Obfuscated forms such as http://3232235777/ or http://0xC0A80001/
    return re.fullmatch(r"0x[0-9a-f]+|\d+", host) is not None


def _has_mixed_script(host_unicode: str) -> bool:
    for label in host_unicode.split("."):
        scripts = {
            unicodedata.name(ch, "UNKNOWN").split()[0] for ch in label if ch.isalpha()
        }
        if len(scripts) > 1:
            return True
    return False


def _normalize(text: str) -> str:
    text = "".join(CONFUSABLES.get(ch, ch) for ch in text.lower())
    return text.replace("rn", "m").replace("vv", "w")


def _is_legit_domain(registered_domain: str) -> bool:
    return any(registered_domain in domains for domains in BRANDS.values())


def _detect_brand(subdomain: str, label: str, registered_domain: str) -> tuple[str, str] | None:
    """Return (brand, how) if this domain looks like it is imitating a known brand."""
    if _is_legit_domain(registered_domain):
        return None

    for token in label.split("-"):
        norm = _normalize(token)
        for brand in BRANDS:
            if token == brand:
                return brand, "brand name in domain"
            if norm == brand:
                return brand, "lookalike characters"
            if len(brand) >= 6 and len(norm) >= 6 and Levenshtein.distance(norm, brand) == 1:
                return brand, "near-match typosquat"

    for token in re.split(r"[.-]", subdomain):
        for brand in BRANDS:
            if token and _normalize(token) == brand:
                return brand, "brand name in subdomain"
    return None


def _anchor_domain(anchor_text: str) -> str | None:
    match = _ANCHOR_RE.search(anchor_text)
    if not match:
        return None
    return _split_host(match.group(1).lower())[3] or None


def _same_brand(a: str, b: str) -> bool:
    return any(a in domains and b in domains for domains in BRANDS.values())


def _build_evidence(f: UrlFeatures) -> list[Evidence]:
    out: list[Evidence] = []

    def obs(statement: str) -> None:
        out.append(Evidence(kind=EvidenceKind.OBSERVED, modality=Modality.URL,
                            statement=statement, source=SOURCE))

    def asm(statement: str) -> None:
        out.append(Evidence(kind=EvidenceKind.ASSESSMENT, modality=Modality.URL,
                            statement=statement, source=SOURCE))

    if f.scheme in DANGEROUS_SCHEMES:
        obs(f"Link uses the '{f.scheme}' scheme")
        asm("Script/data links can run code or hide content; there is no legitimate reason for one in an email")
        return out

    if f.scheme == "http":
        obs("Link uses unencrypted HTTP")
    if f.is_ip_host:
        obs(f"Link points to a raw IP address ({f.host}) instead of a domain name")
        asm("Legitimate brands almost never send email links to bare IP addresses")
    if f.has_userinfo:
        obs(f"URL contains an '@' user-info section; the real host is {f.host}")
        asm("The text before '@' is a known trick to make a link look like a trusted site")
    if f.has_nonstandard_port:
        obs("Link uses a non-standard port")
    if f.is_idn:
        obs(f"Domain uses internationalized characters (displays as {f.host_unicode})")
    if f.has_mixed_script:
        obs("A single domain label mixes characters from different writing systems")
        asm("Mixed-script domains are a classic homograph (look-alike character) attack")
    if f.is_shortener:
        obs(f"Link uses the URL shortener {f.registered_domain}")
        asm("A shortener hides the real destination from the reader and from this static analysis")
    if f.suspicious_tld:
        obs(f"Domain uses the .{f.suffix} top-level domain")
        asm("This TLD is frequently abused, but is a weak signal on its own")
    if f.subdomain_depth >= 4:
        obs(f"Domain has {f.subdomain_depth} subdomain levels")
    if f.brand_impersonated:
        asm(f"Domain appears to imitate {f.brand_impersonated} ({f.impersonation_type}); "
            f"the real registered domain is {f.registered_domain}")
    if f.anchor_mismatch:
        obs(f"Link text shows {f.anchor_domain} but the link goes to {f.registered_domain}")
        asm("Displayed text that names a different site than the link target is a strong deception signal")
    return out


def analyze_url(url: str, anchor_text: str = "") -> UrlAnalysis | None:
    """Static analysis of one URL. Never touches the network. None if unparseable."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        log.warning("Could not parse URL (%d chars)", len(url))
        return None

    host_unicode = _host_unicode(host)
    is_ip = bool(host) and _is_ip(host)

    subdomain = suffix = label = ""
    registered = host
    if host and not is_ip:
        subdomain, label, suffix, registered = _split_host(host_unicode)

    brand = None
    if host and not is_ip:
        brand = _detect_brand(subdomain, label, registered)

    anchor_domain = _anchor_domain(anchor_text) if anchor_text else None
    anchor_mismatch = bool(
        anchor_domain
        and host
        and anchor_domain != registered
        and not _same_brand(anchor_domain, registered)
    )

    features = UrlFeatures(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        host_unicode=host_unicode,
        registered_domain=registered,
        subdomain=subdomain,
        suffix=suffix,
        url_length=len(url),
        subdomain_depth=len(subdomain.split(".")) if subdomain else 0,
        hyphen_count_in_domain=label.count("-"),
        digit_count_in_host=sum(ch.isdigit() for ch in host),
        is_https=parts.scheme.lower() == "https",
        is_ip_host=is_ip,
        has_userinfo="@" in parts.netloc,
        has_nonstandard_port=port is not None and port not in (80, 443),
        is_idn="xn--" in host or not host.isascii(),
        has_mixed_script=_has_mixed_script(host_unicode),
        is_shortener=registered in SHORTENERS,
        suspicious_tld=suffix.split(".")[-1] in SUSPICIOUS_TLDS if suffix else False,
        brand_impersonated=brand[0] if brand else None,
        impersonation_type=brand[1] if brand else None,
        anchor_text=anchor_text,
        anchor_domain=anchor_domain,
        anchor_mismatch=anchor_mismatch,
    )
    return UrlAnalysis(features=features, evidence=_build_evidence(features))