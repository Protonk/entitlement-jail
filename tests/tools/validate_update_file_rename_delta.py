#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def die(message):
    raise SystemExit(f"validate_update_file_rename_delta: {message}")


def require_equal(actual, expected, label):
    if actual != expected:
        die(f"{label}: expected {expected!r}, got {actual!r}")


def require_truthy(value, label):
    if not value:
        die(f"{label}: expected truthy, got {value!r}")


def require_bool(value, label):
    if not isinstance(value, bool):
        die(f"{label}: expected bool, got {type(value).__name__}: {value!r}")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))


def validate_dest_preexisted(doc):
    require_equal(doc.get("normalized_outcome"), "dest_preexisted", "normalized_outcome")
    require_equal(doc.get("dest_preexisted"), True, "dest_preexisted")
    require_equal(doc.get("consume_handle_present"), False, "consume_handle_present")

    candidates = doc.get("update_by_fileid_candidates")
    if candidates != []:
        die(f"update_by_fileid_candidates: expected empty list, got {candidates!r}")

    access = doc.get("access") or {}
    require_truthy(access.get("pre_consume_old") in ("allow", "deny", "not_found", "error"), "access.pre_consume_old present")
    require_truthy(access.get("pre_consume_new") in ("allow", "deny", "not_found", "error"), "access.pre_consume_new present")
    require_equal(access.get("post_consume_old"), None, "access.post_consume_old")
    require_equal(access.get("post_consume_new"), None, "access.post_consume_new")
    require_equal(access.get("after_rename_old"), None, "access.after_rename_old")
    require_equal(access.get("after_rename_new"), None, "access.after_rename_new")
    require_equal(access.get("after_update_file_new"), None, "access.after_update_file_new")


def validate_happy(doc):
    # update_file_rename_delta is a semantics harness: success is an access delta observed, not “rc==0”.
    # The happy fixture encodes: pre-consume deny → post-consume allow (same process context),
    # path-scoped rename does not transfer access to the new path, then update_file(new_path) retargets access.
    require_equal(doc.get("normalized_outcome"), "expected", "normalized_outcome")
    require_equal(doc.get("dest_preexisted"), False, "dest_preexisted")
    require_equal(doc.get("consume_handle_present"), True, "consume_handle_present")
    require_equal(doc.get("rename_was_inode_preserving"), True, "rename_was_inode_preserving")

    access = doc.get("access") or {}
    require_equal(access.get("pre_consume_old"), "deny", "access.pre_consume_old")
    require_equal(access.get("post_consume_old"), "allow", "access.post_consume_old")
    require_equal(access.get("after_rename_old"), "not_found", "access.after_rename_old")
    require_equal(access.get("after_rename_new"), "deny", "access.after_rename_new")
    require_equal(access.get("after_update_file_new"), "allow", "access.after_update_file_new")

    expected_names = [
        "st_ino",
        "st_dev",
        "consume_handle_low32",
        "consume_handle_high32",
        "consume_handle_xor32",
    ]

    candidates = doc.get("update_by_fileid_candidates")
    if not isinstance(candidates, list):
        die(f"update_by_fileid_candidates: expected list, got {type(candidates).__name__}")

    names = [c.get("name") for c in candidates if isinstance(c, dict)]
    require_equal(names, expected_names, "update_by_fileid_candidates names")

    for idx, item in enumerate(candidates):
        if not isinstance(item, dict):
            die(f"candidate[{idx}]: expected object, got {type(item).__name__}")
        require_equal(item.get("attempt_index"), idx, f"candidate[{idx}].attempt_index")
        changed = item.get("changed_access")
        require_bool(changed, f"candidate[{idx}].changed_access")
        require_equal(changed, False, f"candidate[{idx}].changed_access should be false")
        require_equal(item.get("post_new_open"), "deny", f"candidate[{idx}].post_new_open")


def validate_rename_inode_changed(doc):
    # Premise failure: the “rename” did not preserve the inode (same device but different st_ino),
    # so the probe must stop before update_file_by_fileid sweeps and update_file retarget attempts.
    require_equal(doc.get("normalized_outcome"), "rename_inode_changed", "normalized_outcome")
    require_equal(doc.get("dest_preexisted"), False, "dest_preexisted")
    require_equal(doc.get("consume_handle_present"), True, "consume_handle_present")
    require_equal(doc.get("rename_was_inode_preserving"), False, "rename_was_inode_preserving")

    candidates = doc.get("update_by_fileid_candidates")
    if candidates != []:
        die(f"update_by_fileid_candidates: expected empty list (premise failed), got {candidates!r}")

    access = doc.get("access") or {}
    require_equal(access.get("pre_consume_old"), "deny", "access.pre_consume_old")
    require_equal(access.get("post_consume_old"), "allow", "access.post_consume_old")
    require_equal(access.get("after_rename_old"), "not_found", "access.after_rename_old")
    require_equal(access.get("after_rename_new"), "deny", "access.after_rename_new")
    require_equal(access.get("after_update_file_new"), None, "access.after_update_file_new")


def main():
    parser = argparse.ArgumentParser(description="Validate scrubbed update_file_rename_delta fixtures")
    parser.add_argument("--in", dest="input_path", required=True, help="scrubbed fixture JSON")
    parser.add_argument(
        "--expect",
        dest="expect",
        required=True,
        choices=["happy", "dest_preexisted", "rename_inode_changed"],
        help="which fixture invariants to validate",
    )
    args = parser.parse_args()

    doc = load(args.input_path)

    if args.expect == "happy":
        validate_happy(doc)
    elif args.expect == "rename_inode_changed":
        validate_rename_inode_changed(doc)
    else:
        validate_dest_preexisted(doc)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
