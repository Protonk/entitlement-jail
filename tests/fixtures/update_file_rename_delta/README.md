# `update_file_rename_delta` fixtures (how to read them)

These JSON files are **scrubbed** outputs of `sandbox_extension --op update_file_rename_delta` (see `tests/tools/scrub_update_file_rename_delta.py`). They exist to preserve interpretation without adding commentary inside the JSON.

Facts encoded by fields you can see in the fixtures:

- Pre-consume deny vs post-consume allow: `access.pre_consume_old` and `access.post_consume_old` show that `open_read` can be denied before consume and allowed after issue+consume in the same process context.
- Rename can silently change meaning: even for an inode-preserving rename, `access.after_rename_new` remains `deny` (path scope), while `access.after_rename_old` becomes `not_found`.
- `update_file(path)` retargets: `access.after_update_file_new` shows whether access to the new path is restored after `update_file(new_path)`.
- `update_file_by_fileid` return codes are not evidence: per-candidate results live in `update_by_fileid_candidates[]`, and the authoritative signals are `post_new_open` plus `changed_access` (access delta), not “`rc==0`”.
- Uncheatable premises stop the experiment early: premise-failed fixtures keep later phases empty (for example `dest_preexisted.json` has `consume_handle_present: false`, no post-consume/rename/update access fields, and an empty `update_by_fileid_candidates[]`).

Examples:

- `happy.json` is the canonical rename-retarget transcript: pre-consume deny → post-consume allow on the old path → inode-preserving rename does not transfer access to the new path → `update_file(new_path)` restores access.
- `dest_preexisted.json` demonstrates early stop when the destination exists at probe start (premise failure).
- `rename_inode_changed.json` demonstrates early stop when the host-side choreography is not an inode-preserving rename (premise failure).
