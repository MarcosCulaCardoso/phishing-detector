import sys
from pathlib import Path

from app.parsing.parser import parse_eml_bytes
from app.urls.analyzer import analyze_url
from app.urls.extract import defang, extract_urls


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.urls <file.eml>", file=sys.stderr)
        return 2
    email = parse_eml_bytes(Path(argv[1]).read_bytes())
    targets = extract_urls(email)
    print(f"Found {len(targets)} URL(s). Links are defanged; never open them.")
    for target in targets:
        print(f"\nURL: {defang(target.href)}  (from {target.origin})")
        analysis = analyze_url(target.href, target.anchor_text)
        if analysis is None:
            print("  could not be parsed")
            continue
        print(f"  registered domain: {defang(analysis.features.registered_domain)}")
        if not analysis.evidence:
            print("  no indicators found")
        for ev in analysis.evidence:
            print(f"  [{ev.kind.value}] {ev.statement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
