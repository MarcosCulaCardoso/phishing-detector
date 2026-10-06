from html.parser import HTMLParser

from app.parsing.models import Link


class _LinkCollector(HTMLParser):
    """Collects <a href> elements and their visible text. Never renders or fetches."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            anchor = " ".join("".join(self._text).split())
            self.links.append(Link(href=self._href.strip(), anchor_text=anchor))
            self._href = None


def extract_links(html: str) -> list[Link]:
    collector = _LinkCollector()
    collector.feed(html)
    collector.close()
    return collector.links
