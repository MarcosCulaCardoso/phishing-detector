import logging
import re

from app.parsing.models import ParsedEmail
from app.urls.models import UrlTarget

log = logging.getLogger(__name__)

MAX_URLS = 50
MAX_URL_LENGTH = 2048

_URL_RE = re.compile(r"https?://[^\s<>\"'\[\]()]+", re.IGNORECASE)
_TRAILING = ".,;:!?'\""


def extract_urls(email: ParsedEmail) -> list[UrlTarget]:
    """Collect URLs from HTML links (with anchor text) and the plain-text body."""
    candidates: list[tuple[str, str, str]] = [
        (link.href, link.anchor_text, "html") for link in email.links
    ]
    candidates += [(m.group(0), "", "text") for m in _URL_RE.finditer(email.text_body)]

    seen: set[str] = set()
    targets: list[UrlTarget] = []
    for href, anchor, origin in candidates:
        href = href.strip().rstrip(_TRAILING)
        if not href or href in seen or href.lower().startswith("mailto:"):
            continue
        if len(href) > MAX_URL_LENGTH:
            log.warning("Skipping over-long URL (%d chars)", len(href))
            continue
        seen.add(href)
        targets.append(UrlTarget(href=href, anchor_text=anchor, origin=origin))
        if len(targets) >= MAX_URLS:
            log.warning("URL cap of %d reached; ignoring the rest", MAX_URLS)
            break
    return targets


def defang(url: str) -> str:
    """Make a URL safe to print: no clickable links, no accidental visits."""
    return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE).replace(".", "[.]")
