import sys
from pathlib import Path

from app.analysis.report import render_analysis
from app.analysis.scoring import analyze_email
from app.parsing.parser import parse_eml_bytes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.analysis <file.eml>", file=sys.stderr)
        return 2
    try:
        email = parse_eml_bytes(Path(argv[1]).read_bytes())
    except (OSError, ValueError) as exc:
        print(f"error: could not read email: {exc}", file=sys.stderr)
        return 1
    print(render_analysis(analyze_email(email)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
