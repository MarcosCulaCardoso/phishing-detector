import sys
from pathlib import Path

from app.parsing.parser import parse_eml_bytes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.parsing <file.eml>", file=sys.stderr)
        return 2
    parsed = parse_eml_bytes(Path(argv[1]).read_bytes())
    print(parsed.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
