"""Small, hand-curated brand list. Deliberately simple and easy to audit.

Maps a brand keyword to the registered domains that legitimately belong to it.
A real deployment would use a much larger, maintained list.
"""

BRANDS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

# Characters attackers swap in to imitate Latin letters.
CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "$": "s",
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic e
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic er
    "\u0441": "c",  # Cyrillic es
    "\u0445": "x",  # Cyrillic ha
    "\u0443": "y",  # Cyrillic u
    "\u0456": "i",  # Cyrillic Ukrainian i
    "\u0455": "s",  # Cyrillic dze
    "\u04cf": "l",  # Cyrillic palochka
    "\u03bf": "o",  # Greek omicron
}

SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

# A weak signal only: these TLDs are cheap and heavily abused, but many are used legitimately.
SUSPICIOUS_TLDS: set[str] = {
    "zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "ga", "cf", "icu", "cyou",
}
