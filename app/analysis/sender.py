import re

from app.analysis import rules
from app.analysis.models import RuleHit, assessed, observed
from app.parsing.models import ParsedEmail
from app.schemas import Modality
from app.urls.brands import BRANDS
from app.urls.extract import defang

SOURCE = "sender_rules"

# Authentication-Results can be added by any server the message passed through,
# including one the attacker controls. It is only trustworthy if our own receiving
# mail server added it, so we record what it says as an observed fact, nothing more.
_AUTH_RE = re.compile(r"\b(spf|dkim)\s*=\s*([a-z]+)", re.IGNORECASE)
_AUTH_FAILURES = {"fail", "softfail", "permerror"}


def _same_org(a: str, b: str) -> bool:
    """True if the domains are equal or one is a subdomain of the other."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _reply_to_mismatch(email: ParsedEmail) -> RuleHit | None:
    from_domain = email.sender.domain
    if not from_domain:
        return None
    for addr in email.reply_to:
        if addr.domain and not _same_org(addr.domain, from_domain):
            return RuleHit(rule="reply_to_mismatch", points=rules.REPLY_TO_MISMATCH, evidence=[
                observed(Modality.SENDER, f"Reply-To domain {defang(addr.domain)} differs "
                         f"from From domain {defang(from_domain)}", SOURCE),
            ])
    return None


def _brand_in_name(display_name: str) -> str | None:
    words = re.findall(r"[a-z0-9]+", display_name.lower())
    joined = "".join(words)  # "Bank of America" -> "bankofamerica"
    for brand in BRANDS:
        if brand in words or (len(brand) >= 8 and brand in joined):
            return brand
    return None


def _display_name_brand(email: ParsedEmail) -> RuleHit | None:
    domain = email.sender.domain
    brand = _brand_in_name(email.sender.display_name)
    if not brand or not domain:
        return None
    if any(_same_org(domain, legit) for legit in BRANDS[brand]):
        return None
    return RuleHit(rule="display_name_brand", points=rules.DISPLAY_NAME_BRAND, evidence=[
        observed(Modality.SENDER, f"Sender display name mentions {brand} but the address "
                 f"is at {defang(domain)}", SOURCE),
        assessed(Modality.SENDER, "Display names are chosen freely by the sender; "
                 "this one claims a brand the address doesn't belong to", SOURCE),
    ])


def _auth_failures(email: ParsedEmail) -> list[RuleHit]:
    points = {"spf": rules.SPF_FAIL, "dkim": rules.DKIM_FAIL}
    hits: dict[str, RuleHit] = {}
    for header in email.authentication_results:
        for mechanism, result in _AUTH_RE.findall(header):
            mechanism, result = mechanism.lower(), result.lower()
            if result in _AUTH_FAILURES and mechanism not in hits:
                hits[mechanism] = RuleHit(rule=f"{mechanism}_fail", points=points[mechanism], evidence=[
                    observed(Modality.SENDER, f"Authentication-Results header records "
                             f"{mechanism}={result}", SOURCE),
                ])
    return list(hits.values())


def check_sender(email: ParsedEmail) -> list[RuleHit]:
    found = [_reply_to_mismatch(email), _display_name_brand(email)]
    return [hit for hit in found if hit] + _auth_failures(email)
