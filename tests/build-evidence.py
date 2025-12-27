#!/usr/bin/env python3
import argparse
import hashlib
import json
import plistlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def lc_uuid(path: Path) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["/usr/bin/dwarfdump", "--uuid", str(path)],
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "UUID:":
            return parts[1]
    return None


def _extract_plist_bytes(blob: bytes) -> Optional[bytes]:
    idx = blob.find(b"<?xml")
    if idx == -1:
        idx = blob.find(b"<plist")
    if idx == -1:
        return None
    return blob[idx:]


def _parse_codesign_entitlements_text(text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    current_key: Optional[str] = None
    array_stack: list[Tuple[int, list[Any]]] = []

    for raw in text.splitlines():
        if not raw:
            continue
        if raw.startswith("Executable="):
            continue

        stripped = raw.lstrip("\t")
        indent = len(raw) - len(stripped)

        while array_stack and indent <= array_stack[-1][0]:
            array_stack.pop()

        if stripped.startswith("[Key] "):
            current_key = stripped[len("[Key] "):].strip()
            continue
        if stripped.startswith("[Value]"):
            continue
        if stripped.startswith("[Array]"):
            if current_key:
                arr: list[Any] = []
                result[current_key] = arr
                array_stack.append((indent, arr))
                current_key = None
            continue
        if stripped.startswith("[Bool] "):
            val = stripped[len("[Bool] "):].strip().lower() == "true"
            if array_stack:
                array_stack[-1][1].append(val)
            elif current_key:
                result[current_key] = val
                current_key = None
            continue
        if stripped.startswith("[String] "):
            val = stripped[len("[String] "):].strip()
            if array_stack:
                array_stack[-1][1].append(val)
            elif current_key:
                result[current_key] = val
                current_key = None
            continue
        if stripped.startswith("[Integer] "):
            try:
                val = int(stripped[len("[Integer] "):].strip())
            except ValueError:
                continue
            if array_stack:
                array_stack[-1][1].append(val)
            elif current_key:
                result[current_key] = val
                current_key = None
            continue
    return result

def entitlements_from_codesign(path: Path) -> Tuple[Dict[str, Any], Optional[str]]:
    try:
        proc = subprocess.run(
            ["/usr/bin/codesign", "-d", "--entitlements", "-", "--", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {}, f"codesign failed: {exc}"

    combined = proc.stdout + proc.stderr
    plist_bytes = _extract_plist_bytes(combined)
    if plist_bytes:
        try:
            data = plistlib.loads(plist_bytes)
        except Exception as exc:  # noqa: BLE001
            return {}, f"entitlements parse error: {exc}"
        if isinstance(data, dict):
            return data, None
        return {}, "entitlements parse error: unexpected plist type"

    text = combined.decode("utf-8", errors="ignore")
    parsed = _parse_codesign_entitlements_text(text)
    if parsed:
        return parsed, None
    return {}, "entitlements parse error: not found"


def profile_id_for_service(service_name: str) -> str:
    if service_name.startswith("ProbeService_"):
        suffix = service_name[len("ProbeService_") :]
        return suffix.lower()
    if service_name.startswith("QuarantineLab_"):
        suffix = service_name[len("QuarantineLab_") :]
        return f"quarantine_{suffix.lower()}"
    return service_name.lower()


def label_for_profile(profile_id: str) -> str:
    return profile_id.replace("_", " ")


def tags_for_profile(service_name: str, entitlements: Dict[str, Any]) -> list[str]:
    tags: list[str] = []
    kind = "probe" if service_name.startswith("ProbeService_") else "quarantine" if service_name.startswith("QuarantineLab_") else "other"
    tags.append(kind)
    if entitlements.get("com.apple.security.app-sandbox") is True:
        tags.append("sandbox")
    if service_name.endswith("_minimal") or service_name.endswith("_default"):
        tags.append("baseline")
    if entitlements.get("com.apple.security.network.client") is True:
        tags.append("network_client")
    if entitlements.get("com.apple.security.files.downloads.read-write") is True:
        tags.append("downloads_rw")
    if entitlements.get("com.apple.security.files.user-selected.executable") is True:
        tags.append("user_selected_executable")
    if entitlements.get("com.apple.security.files.bookmarks.app-scope") is True:
        tags.append("bookmarks_app_scope")
    if entitlements.get("com.apple.security.get-task-allow") is True:
        tags.append("get_task_allow")
    if entitlements.get("com.apple.security.cs.disable-library-validation") is True:
        tags.append("disable_library_validation")
    if entitlements.get("com.apple.security.cs.allow-dyld-environment-variables") is True:
        tags.append("dyld_env")
    if entitlements.get("com.apple.security.cs.allow-jit") is True:
        tags.append("jit")
    if entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory") is True:
        tags.append("rwx_legacy")
    return sorted(set(tags))


def risk_for_entitlements(entitlements: Dict[str, Any]) -> Tuple[int, list[str]]:
    reasons: list[str] = []
    if entitlements.get("com.apple.security.cs.allow-dyld-environment-variables") is True:
        reasons.append("allow_dyld_env")
    if entitlements.get("com.apple.security.cs.allow-jit") is True:
        reasons.append("allow_jit")
    if entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory") is True:
        reasons.append("allow_unsigned_exec_mem")
    if reasons:
        return 2, reasons

    if entitlements.get("com.apple.security.get-task-allow") is True:
        reasons.append("get_task_allow")
    if entitlements.get("com.apple.security.cs.disable-library-validation") is True:
        reasons.append("disable_library_validation")
    if reasons:
        return 1, reasons

    return 0, []


def exported_ej_symbols(path: Path) -> Tuple[list[str], Optional[str]]:
    try:
        out = subprocess.check_output(
            ["/usr/bin/nm", "-g", str(path)],
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return [], f"nm failed: {exc}"

    symbols = set()
    for line in out.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if len(parts) == 2 and parts[0] == "U":
            continue
        sym_type = parts[-2] if len(parts) >= 2 else ""
        if sym_type == "U":
            continue
        sym = parts[-1]
        if sym.startswith("_ej_"):
            symbols.add(sym[1:])
    return sorted(symbols), None


def read_plist(path: Path) -> Dict[str, Any]:
    with path.open("rb") as fh:
        data = plistlib.load(fh)
    if isinstance(data, dict):
        return data
    return {}


def rel_path(app_root: Path, target: Path) -> str:
    return str(target.relative_to(app_root))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Evidence BOM for EntitlementJail.app")
    parser.add_argument("--app-bundle", required=True, help="Path to EntitlementJail.app")
    parser.add_argument("--app-entitlements", required=True, help="Path to main app entitlements plist")
    args = parser.parse_args()

    app_bundle = Path(args.app_bundle).resolve()
    contents_dir = app_bundle / "Contents"
    evidence_dir = contents_dir / "Resources" / "Evidence"
    xpc_dir = contents_dir / "XPCServices"

    if not contents_dir.exists():
        print(f"ERROR: missing app bundle Contents: {contents_dir}", file=sys.stderr)
        return 2

    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    app_info = read_plist(contents_dir / "Info.plist")
    app_bundle_id = app_info.get("CFBundleIdentifier")
    app_entitlements = read_plist(Path(args.app_entitlements))

    entries = []

    helper_names = ["xpc-probe-client", "xpc-quarantine-client", "sandbox-log-observer"]
    for name in helper_names:
        helper_path = contents_dir / "MacOS" / name
        if not helper_path.exists():
            continue
        entitlements, err = entitlements_from_codesign(helper_path)
        entry = {
            "id": name,
            "kind": "helper",
            "rel_path": rel_path(app_bundle, helper_path),
            "sha256": sha256_file(helper_path),
            "lc_uuid": lc_uuid(helper_path) or "",
            "entitlements": entitlements,
        }
        if err:
            entry["entitlements_error"] = err
        entries.append(entry)

    if xpc_dir.exists():
        for svc_bundle in sorted(xpc_dir.glob("*.xpc")):
            info_path = svc_bundle / "Contents" / "Info.plist"
            if not info_path.exists():
                continue
            info = read_plist(info_path)
            bundle_id = info.get("CFBundleIdentifier")
            svc_name = svc_bundle.stem
            svc_bin = svc_bundle / "Contents" / "MacOS" / svc_name
            if not svc_bin.exists():
                continue
            entitlements, err = entitlements_from_codesign(svc_bin)
            entry = {
                "id": bundle_id or svc_name,
                "bundle_id": bundle_id,
                "kind": "xpc-service",
                "service_name": svc_name,
                "rel_path": rel_path(app_bundle, svc_bin),
                "sha256": sha256_file(svc_bin),
                "lc_uuid": lc_uuid(svc_bin) or "",
                "entitlements": entitlements,
            }
            if err:
                entry["entitlements_error"] = err
            entries.append(entry)

    symbols_entries = []
    for entry in entries:
        abs_path = app_bundle / entry["rel_path"]
        syms, err = exported_ej_symbols(abs_path)
        if err:
            symbols_entries.append({
                "id": entry["id"],
                "bundle_id": entry.get("bundle_id"),
                "rel_path": entry["rel_path"],
                "symbols": [],
                "error": err,
            })
            continue
        if syms:
            symbols_entries.append({
                "id": entry["id"],
                "bundle_id": entry.get("bundle_id"),
                "rel_path": entry["rel_path"],
                "symbols": syms,
            })

    symbols_manifest = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": symbols_entries,
    }
    symbols_path = evidence_dir / "symbols.json"
    with symbols_path.open("w", encoding="utf-8") as fh:
        json.dump(symbols_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    entries.append({
        "id": "evidence.symbols",
        "kind": "evidence",
        "rel_path": rel_path(app_bundle, symbols_path),
        "sha256": sha256_file(symbols_path),
    })

    profiles = []
    for entry in entries:
        if entry.get("kind") != "xpc-service":
            continue
        service_name = entry.get("service_name") or ""
        if not service_name:
            continue
        entitlements = entry.get("entitlements") or {}
        risk_tier, risk_reasons = risk_for_entitlements(entitlements)
        if entry.get("entitlements_error"):
            risk_tier = max(risk_tier, 2)
            if "entitlements_error" not in risk_reasons:
                risk_reasons.append("entitlements_error")
        profile_id = profile_id_for_service(service_name)
        profiles.append({
            "profile_id": profile_id,
            "bundle_id": entry.get("bundle_id") or entry["id"],
            "service_name": service_name,
            "kind": "probe" if service_name.startswith("ProbeService_") else "quarantine" if service_name.startswith("QuarantineLab_") else "other",
            "label": label_for_profile(profile_id),
            "tags": tags_for_profile(service_name, entitlements),
            "risk_tier": risk_tier,
            "risk_reasons": risk_reasons,
            "entitlements": entitlements,
            "entitlements_error": entry.get("entitlements_error"),
        })

    profiles_manifest = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "profiles": profiles,
    }
    profiles_path = evidence_dir / "profiles.json"
    with profiles_path.open("w", encoding="utf-8") as fh:
        json.dump(profiles_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    entries.append({
        "id": "evidence.profiles",
        "kind": "evidence",
        "rel_path": rel_path(app_bundle, profiles_path),
        "sha256": sha256_file(profiles_path),
    })

    manifest = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app_bundle_id": app_bundle_id,
        "app_binary_rel_path": "Contents/MacOS/entitlement-jail",
        "app_entitlements": app_entitlements,
        "entries": entries,
        "notes": [
            "Main app binary hash is omitted because the manifest is signed by the app bundle.",
        ],
    }

    manifest_path = evidence_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
