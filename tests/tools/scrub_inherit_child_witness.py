#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

def classify_op(op):
    if not isinstance(op, dict):
        return None
    rc = op.get("rc")
    errno = op.get("errno")
    if rc is None:
        return {"rc_class": "missing"}
    if rc == 0:
        return {"rc_class": "ok"}
    if errno in (1, 13):
        return {"rc_class": "deny"}
    return {"rc_class": "err"}


def classify_rc(rc, errno=None):
    if rc is None:
        return None
    if rc == 0:
        return "ok"
    if errno in (1, 13):
        return "deny"
    return "err"


def scrub_bookmark(bookmark):
    if not isinstance(bookmark, dict):
        return None
    resolve_rc = bookmark.get("resolve_rc")
    access_rc = bookmark.get("access_rc")
    return {
        "resolve_rc": classify_rc(resolve_rc),
        "resolve_error_present": bool(bookmark.get("resolve_error")),
        "resolve_error_domain_present": bool(bookmark.get("resolve_error_domain")),
        "resolve_error_code_present": bookmark.get("resolve_error_code") is not None,
        "is_stale": bookmark.get("is_stale"),
        "start_accessing": bookmark.get("start_accessing"),
        "access_rc": classify_rc(access_rc, bookmark.get("access_errno")),
    }


def scrub_events(events):
    out = []
    for event in events:
        if not isinstance(event, dict):
            continue
        lineage = event.get("lineage") or {}
        out.append({
            "actor": event.get("actor"),
            "phase": event.get("phase"),
            "lineage_depth": lineage.get("depth"),
            "callsite": bool(event.get("callsite_id")),
            "op": bool(event.get("op")),
            "deny": event.get("errno") in (1, 13),
            "backtrace": bool(event.get("backtrace")),
            "backtrace_error": bool(event.get("backtrace_error")),
        })
    return out


def scrub_witness(envelope):
    result = envelope.get("result") or {}
    witness = (envelope.get("data") or {}).get("witness") or {}
    capability_results = []
    for cap in witness.get("capability_results") or []:
        if not isinstance(cap, dict):
            continue
        capability_results.append({
            "cap_id": cap.get("cap_id"),
            "cap_type": cap.get("cap_type"),
            "notes": cap.get("notes") or "",
            "parent_acquire": classify_op(cap.get("parent_acquire")),
            "child_acquire": classify_op(cap.get("child_acquire")),
            "child_use": classify_op(cap.get("child_use")),
            "bookmark": scrub_bookmark(cap.get("bookmark")),
        })
    capability_results.sort(key=lambda item: item.get("cap_id") or "")

    entitlements = witness.get("child_entitlements") or {}
    ent_keys = sorted(entitlements.keys()) if isinstance(entitlements, dict) else []

    protocol_error = witness.get("protocol_error") or None
    protocol_scrub = None
    if isinstance(protocol_error, dict):
        protocol_scrub = {
            "kind": protocol_error.get("kind"),
            "expected_present": protocol_error.get("expected") is not None,
            "observed_present": protocol_error.get("observed") is not None,
        }

    child_exit_status = witness.get("child_exit_status")
    if isinstance(child_exit_status, int):
        exit_kind = "signal" if child_exit_status >= 128 else "exit"
    else:
        exit_kind = None

    return {
        "schema_version": witness.get("schema_version"),
        "protocol_version": witness.get("protocol_version"),
        "capability_namespace": witness.get("capability_namespace"),
        "scenario": witness.get("scenario"),
        "normalized_outcome": result.get("normalized_outcome"),
        "outcome_summary": witness.get("outcome_summary"),
        "inherit_contract_ok": witness.get("inherit_contract_ok"),
        "child_entitlements_keys": ent_keys,
        "child_exit_kind": exit_kind,
        "child_event_fd_present": isinstance(witness.get("child_event_fd"), int),
        "child_rights_fd_present": isinstance(witness.get("child_rights_fd"), int),
        "sandbox_log_capture_status": witness.get("sandbox_log_capture_status"),
        "capability_results": capability_results,
        "events": scrub_events(witness.get("events") or []),
        "protocol_error": protocol_scrub,
    }


def main():
    parser = argparse.ArgumentParser(description="Scrub inherit_child witness into a stable fixture")
    parser.add_argument("--in", dest="input_path", required=True, help="probe response JSON")
    parser.add_argument("--out", dest="output_path", required=True, help="scrubbed fixture JSON")
    args = parser.parse_args()

    data = json.loads(Path(args.input_path).read_text(encoding="utf-8", errors="replace"))
    scrubbed = scrub_witness(data)

    out_path = Path(args.output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(scrubbed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
