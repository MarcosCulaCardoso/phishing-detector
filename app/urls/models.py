from pydantic import BaseModel, Field

from app.schemas import Evidence


class UrlTarget(BaseModel):
    """A URL found in an email, plus the text a reader sees for it (if any)."""

    href: str
    anchor_text: str = ""
    origin: str = "text"  # "html" or "text"


class UrlFeatures(BaseModel):
    url: str
    scheme: str
    host: str
    host_unicode: str
    registered_domain: str
    subdomain: str
    suffix: str
    url_length: int
    subdomain_depth: int
    hyphen_count_in_domain: int
    digit_count_in_host: int
    is_https: bool
    is_ip_host: bool
    has_userinfo: bool
    has_nonstandard_port: bool
    is_idn: bool
    has_mixed_script: bool
    is_shortener: bool
    suspicious_tld: bool
    brand_impersonated: str | None = None
    impersonation_type: str | None = None
    anchor_text: str = ""
    anchor_domain: str | None = None
    anchor_mismatch: bool = False


class UrlAnalysis(BaseModel):
    features: UrlFeatures
    evidence: list[Evidence] = Field(default_factory=list)
