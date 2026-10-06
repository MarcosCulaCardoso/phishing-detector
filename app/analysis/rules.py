"""Point values and verdict thresholds for the rule-based analyzer.

Hand-picked starting values, NOT tuned or calibrated on real data.
Each rule counts at most once per email, however many times it matches.
"""

# --- Links ---
DANGEROUS_SCHEME = 40  # javascript:/data: links can run code; no legitimate email needs one
ANCHOR_MISMATCH = 30  # visible link text names a different site than the real target
BRAND_LOOKALIKE = 25  # link domain imitates a known brand (lookalike chars, typo, subdomain)
USERINFO_TRICK = 25  # text before '@' in a URL disguises the real host
MIXED_SCRIPT = 20  # one domain label mixes alphabets: homograph attack
IP_HOST = 20  # real organizations almost never link to a bare IP address
SHORTENER = 10  # hides the destination, but marketing mail uses shorteners too
PLAIN_HTTP = 5  # unencrypted link; weak on its own
SUSPICIOUS_TLD = 5  # frequently abused ending such as .xyz; weak on its own
NONSTANDARD_PORT = 5  # unusual port; weak on its own

# --- Sender and headers ---
REPLY_TO_MISMATCH = 15  # replies go to a different domain; some helpdesks do this legitimately
DISPLAY_NAME_BRAND = 20  # display name claims a brand the sending address doesn't belong to
SPF_FAIL = 15  # sending server not authorized for the envelope domain
DKIM_FAIL = 15  # message signature missing a valid match or altered in transit

# --- Attachments (metadata only) ---
DOUBLE_EXTENSION = 40  # e.g. invoice.pdf.exe: a program disguised as a document
RISKY_EXTENSION = 30  # file types that run code when opened

# --- Text (always ASSESSMENT) ---
CREDENTIAL_REQUEST = 20  # asks for passwords, account verification, or payment
URGENCY = 10  # pressure or threats; legitimate mail uses these words too, so low weight

# --- Verdict thresholds ---
# One strong signal alone -> suspicious; two independent strong signals -> phishing.
SUSPICIOUS_THRESHOLD = 25
PHISHING_THRESHOLD = 50
MAX_SCORE = 100
