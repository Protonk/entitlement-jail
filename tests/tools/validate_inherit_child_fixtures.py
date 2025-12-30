#!/usr/bin/env python3
import json
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "inherit_child"

REQUIRED_KEYS = {
    "schema_version",
    "protocol_version",
    "capability_namespace",
    "scenario",
    "normalized_outcome",
    "outcome_summary",
    "inherit_contract_ok",
    "child_entitlements_keys",
    "child_exit_kind",
    "child_event_fd_present",
    "child_rights_fd_present",
    "sandbox_log_capture_status",
    "capability_results",
    "events",
    "protocol_error",
}

errors = []
if not FIXTURE_DIR.exists():
    errors.append(f"missing fixture directory: {FIXTURE_DIR}")
else:
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: failed to parse JSON: {exc}")
            continue
        missing = REQUIRED_KEYS - set(data.keys())
        if missing:
            errors.append(f"{path.name}: missing keys {sorted(missing)}")
        scenario = data.get("scenario")
        expected = path.stem
        if scenario != expected:
            errors.append(f"{path.name}: scenario mismatch (expected {expected}, got {scenario})")

if errors:
    for err in errors:
        print(f"ERROR: {err}", file=sys.stderr)
    sys.exit(1)
