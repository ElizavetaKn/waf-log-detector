from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .detector import inspect_request


REQUEST_RE = re.compile(r'"(?P<request>(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+[^"]+)"')


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze HTTP access logs")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, default=Path("waf-alerts.json"))
    args = parser.parse_args()

    results: list[dict[str, str | int]] = []
    for line_no, line in enumerate(args.input.read_text(encoding="utf-8").splitlines(), 1):
        match = REQUEST_RE.search(line)
        if not match:
            continue
        request = match.group("request")
        for detection in inspect_request(request):
            item = detection.to_dict()
            item["line"] = line_no
            results.append(item)

    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Detections: {len(results)}")


if __name__ == "__main__":
    main()
