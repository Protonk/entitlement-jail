#!/usr/bin/env python3
import json
import sys
from pathlib import Path
import difflib

if len(sys.argv) != 3:
    print("usage: compare_json_fixture.py <actual.json> <fixture.json>", file=sys.stderr)
    sys.exit(2)

actual_path = Path(sys.argv[1])
fixture_path = Path(sys.argv[2])

actual = json.loads(actual_path.read_text(encoding="utf-8", errors="replace"))
fixture = json.loads(fixture_path.read_text(encoding="utf-8", errors="replace"))

if actual != fixture:
    actual_text = json.dumps(actual, indent=2, sort_keys=True).splitlines()
    fixture_text = json.dumps(fixture, indent=2, sort_keys=True).splitlines()
    diff = "\n".join(difflib.unified_diff(fixture_text, actual_text, fromfile=str(fixture_path), tofile=str(actual_path)))
    print(diff)
    sys.exit(1)
