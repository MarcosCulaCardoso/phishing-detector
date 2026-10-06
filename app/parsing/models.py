from pydantic import BaseModel, Field


class Address(BaseModel):
    display_name: str = ""
    email: str = ""

    @property
    def domain(self) -> str:
        return self.email.rpartition("@")[2]


class Link(BaseModel):
    href: str
    anchor_text: str = ""


class AttachmentInfo(BaseModel):
    """Metadata only. Attachment contents are never stored or executed."""

    filename: str | None
    content_type: str
    size_bytes: int
    sha256: str


class ParsedEmail(BaseModel):
    subject: str = ""
    sender: Address = Field(default_factory=Address)
    reply_to: list[Address] = Field(default_factory=list)
    to: list[Address] = Field(default_factory=list)
    return_path: str | None = None
    date: str | None = None
    message_id: str | None = None
    authentication_results: list[str] = Field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)
