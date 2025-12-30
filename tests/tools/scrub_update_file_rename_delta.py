#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_int(value):
    try:
        return int(value)
    except Exception:
        return None


def parse_bool(value):
    if value is True:
        return True
    if value is False:
        return False
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def classify_open_outcome(outcome):
    if outcome in ("allow", "deny", "not_found"):
        return outcome
    if outcome is None:
        return None
    return "error"


def classify_norm_errno(norm_errno):
    if norm_errno is None:
        return None
    if norm_errno == 0:
        return "ok"
    if norm_errno == 22:
        return "EINVAL"
    if norm_errno == 2:
        return "ENOENT"
    if norm_errno == 14:
        return "EFAULT"
    return f"err_{norm_errno}"


def scrub(envelope):
    result = envelope.get("result") or {}
    data = envelope.get("data") or {}
    details = data.get("details") or {}

    out = {
        "normalized_outcome": result.get("normalized_outcome"),
        "dest_preexisted": parse_bool(details.get("dest_preexisted")),
        "consume_handle_present": "consume_handle" in details,
        "rename_was_inode_preserving": parse_bool(details.get("rename_was_inode_preserving")),
        "delta_old_open_transition": details.get("delta_old_open_transition"),
        "delta_new_open_transition": details.get("delta_new_open_transition"),
        "access": {
            "pre_consume_old": classify_open_outcome(details.get("access_pre_consume_old_open_outcome")),
            "pre_consume_new": classify_open_outcome(details.get("access_pre_consume_new_open_outcome")),
            "post_consume_old": classify_open_outcome(details.get("access_post_consume_old_open_outcome")),
            "post_consume_new": classify_open_outcome(details.get("access_post_consume_new_open_outcome")),
            "after_rename_old": classify_open_outcome(details.get("access_after_rename_old_open_outcome")),
            "after_rename_new": classify_open_outcome(details.get("access_after_rename_new_open_outcome")),
            "after_update_file_new": classify_open_outcome(details.get("access_after_update_file_new_open_outcome")),
        },
        "update_by_fileid_candidates": [],
    }

    candidate_count = parse_int(details.get("update_by_fileid_candidate_count"))
    if isinstance(candidate_count, int) and candidate_count >= 0:
        for idx in range(candidate_count):
            name = details.get(f"update_by_fileid_candidate_{idx}_name")
            if not name:
                continue
            norm_errno = parse_int(details.get(f"update_by_fileid_{name}_norm_errno"))
            out["update_by_fileid_candidates"].append(
                {
                    "name": name,
                    "attempt_index": parse_int(details.get(f"update_by_fileid_{name}_attempt_index")),
                    "norm_errno_class": classify_norm_errno(norm_errno),
                    "changed_access": parse_bool(details.get(f"update_by_fileid_{name}_changed_access")),
                    "post_new_open": classify_open_outcome(
                        details.get(f"access_after_update_by_fileid_{name}_new_open_outcome")
                    ),
                }
            )

    out["update_by_fileid_candidates"].sort(
        key=lambda item: (item.get("attempt_index") is None, item.get("attempt_index"), item.get("name") or "")
    )
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Scrub sandbox_extension update_file_rename_delta output into a stable fixture"
    )
    parser.add_argument("--in", dest="input_path", required=True, help="probe response JSON")
    parser.add_argument("--out", dest="output_path", required=True, help="scrubbed fixture JSON")
    args = parser.parse_args()

    data = json.loads(Path(args.input_path).read_text(encoding="utf-8", errors="replace"))
    scrubbed = scrub(data)

    out_path = Path(args.output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(scrubbed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

