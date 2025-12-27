mod debug_entitlements_probe;
mod evidence;
mod json_contract;
mod profiles;

use serde::Serialize;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::{env, process::Command};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn print_usage() {
    eprintln!(
        "\
usage:
  entitlement-jail run-system <absolute-platform-binary> [args...]
  entitlement-jail run-embedded <tool-name> [args...]
  entitlement-jail xpc run (--profile <id> | --service <bundle-id>) [--ack-risk <id|bundle-id>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] <probe-id> [probe-args...]
  entitlement-jail xpc session (--profile <id> | --service <bundle-id>) [--ack-risk <id|bundle-id>] [--plan-id <id>] [--correlation-id <id>] [--wait <fifo:auto|fifo:/abs|exists:/abs>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--xpc-timeout-ms <n>]
  entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
  entitlement-jail verify-evidence
  entitlement-jail inspect-macho <service-id|main|path>
  entitlement-jail list-profiles
  entitlement-jail list-services
  entitlement-jail show-profile <id>
  entitlement-jail describe-service <id>
  entitlement-jail health-check [--profile <id>]
  entitlement-jail bundle-evidence [--out <dir>] [--include-health-check] [--ack-risk <id|bundle-id>]
  entitlement-jail run-matrix --group <name> [--out <dir>] [--ack-risk <id|bundle-id>] <probe-id> [probe-args...]

notes:
  - run-system only allows platform-style paths (/bin, /usr/bin, /sbin, /usr/sbin, /usr/libexec, /System/Library)
  - run-embedded looks for signed helper tools in this app bundle (Contents/Helpers and Contents/Helpers/Probes)"
    );
}

#[derive(Serialize)]
struct InspectEntry {
    id: String,
    kind: String,
    bundle_id: Option<String>,
    rel_path: String,
    abs_path: String,
    sha256: Option<String>,
    lc_uuid: Option<String>,
    entitlements: Option<serde_json::Value>,
    entitlements_error: Option<String>,
}

#[derive(Serialize)]
struct InspectReport {
    selector: String,
    app_root: String,
    manifest_path: String,
    entry: InspectEntry,
}

#[derive(Serialize)]
struct ProfilesReport {
    profiles_path: String,
    generated_at: Option<String>,
    profiles: Vec<profiles::ProfileEntry>,
}

#[derive(Serialize)]
struct ProfileReport {
    profiles_path: String,
    profile: profiles::ProfileEntry,
}

#[derive(Serialize)]
struct HealthProbeResult {
    probe_id: String,
    rc: Option<i64>,
    normalized_outcome: Option<String>,
    error: Option<String>,
    exit_code: i32,
    parse_error: Option<String>,
    stderr: Option<String>,
}

#[derive(Serialize)]
struct HealthProfileResult {
    profile_id: String,
    bundle_id: String,
    kind: String,
    ok: bool,
    probes: Vec<HealthProbeResult>,
}

#[derive(Serialize)]
struct HealthCheckReport {
    ok: bool,
    profiles_path: String,
    profiles: Vec<HealthProfileResult>,
}

#[derive(Serialize)]
struct ServicesReport {
    profiles_path: String,
    generated_at: Option<String>,
    services: Vec<profiles::ProfileEntry>,
}

#[derive(Serialize)]
struct ServiceCapabilities {
    has_app_sandbox: bool,
    has_get_task_allow: bool,
    has_disable_library_validation: bool,
    has_allow_dyld_env: bool,
    has_allow_jit: bool,
    has_allow_unsigned_exec_mem: bool,
    has_network_client: bool,
    has_downloads_rw: bool,
    has_bookmarks_app_scope: bool,
    has_user_selected_read_only: bool,
    has_user_selected_read_write: bool,
    has_user_selected_executable: bool,
    home_dir: String,
    tmp_dir: String,
    downloads_dir: String,
    desktop_dir: String,
    documents_dir: String,
    app_support_dir: String,
    caches_dir: String,
    prefs_path_guess: String,
}

#[derive(Serialize)]
struct DescribeServiceReport {
    service: profiles::ProfileEntry,
    capabilities_source: String,
    capabilities: ServiceCapabilities,
}

#[derive(Serialize, Clone)]
struct MatrixRun {
    profile_id: String,
    bundle_id: String,
    label: Option<String>,
    risk_tier: Option<u8>,
    risk_reasons: Option<Vec<String>>,
    exit_code: i32,
    duration_ms: u128,
    rc: Option<i64>,
    normalized_outcome: Option<String>,
    error: Option<String>,
    parse_error: Option<String>,
    response: Option<serde_json::Value>,
}

#[derive(Serialize, Clone)]
struct MatrixSkip {
    profile_id: String,
    bundle_id: String,
    reason: String,
    risk_tier: Option<u8>,
    risk_reasons: Option<Vec<String>>,
}

#[derive(Serialize)]
struct RunMatrixReport {
    group_id: String,
    probe_id: String,
    probe_argv: Vec<String>,
    generated_at_unix_ms: u128,
    output_dir: String,
    profiles: Vec<String>,
    runs: Vec<MatrixRun>,
    skipped: Vec<MatrixSkip>,
}

#[derive(Serialize)]
struct BundleProfileSkip {
    profile_id: String,
    bundle_id: String,
    reason: String,
    risk_tier: Option<u8>,
    risk_reasons: Option<Vec<String>>,
}

#[derive(Serialize)]
struct BundleMeta {
    generated_at_unix_ms: u128,
    app_root: String,
    app_bundle_id: Option<String>,
    output_dir: String,
    args: Vec<String>,
    include_health_check: bool,
    ack_risk: Vec<String>,
    verify_ok: bool,
    health_ok: Option<bool>,
    profiles_included: Vec<String>,
    profiles_skipped: Vec<BundleProfileSkip>,
}

#[derive(Clone, Copy)]
enum RiskGate {
    Allow,
    Warn,
    RequireAck,
}

fn risk_gate_for_profile(profile: Option<&profiles::ProfileEntry>) -> (RiskGate, Vec<String>, Option<String>) {
    match profile {
        None => (
            RiskGate::RequireAck,
            vec!["unknown_profile".to_string()],
            None,
        ),
        Some(profile) => {
            let tier = profile.risk_tier.unwrap_or(2);
            let reasons = profile.risk_reasons.clone().unwrap_or_else(Vec::new);
            let label = profile.label.clone();
            match tier {
                0 => (RiskGate::Allow, reasons, label),
                1 => (RiskGate::Warn, reasons, label),
                _ => (RiskGate::RequireAck, reasons, label),
            }
        }
    }
}

fn resolve_profile_by_bundle_id<'a>(
    manifest: &'a profiles::ProfilesManifest,
    bundle_id: &str,
) -> Option<&'a profiles::ProfileEntry> {
    manifest
        .profiles
        .iter()
        .find(|profile| profile.bundle_id == bundle_id)
}

fn entitlement_bool(entitlements: &Option<serde_json::Value>, key: &str) -> bool {
    match entitlements {
        Some(serde_json::Value::Object(map)) => match map.get(key) {
            Some(serde_json::Value::Bool(v)) => *v,
            Some(serde_json::Value::String(v)) => v == "true",
            _ => false,
        },
        _ => false,
    }
}

fn container_base_dir(bundle_id: &str) -> Option<PathBuf> {
    let home = env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Containers")
            .join(bundle_id)
            .join("Data"),
    )
}

fn container_path(base: &Option<PathBuf>, parts: &[&str]) -> String {
    let mut path = match base {
        Some(base) => base.clone(),
        None => return String::new(),
    };
    for part in parts {
        path = path.join(part);
    }
    path.display().to_string()
}

fn build_static_capabilities(profile: &profiles::ProfileEntry) -> ServiceCapabilities {
    let base = container_base_dir(&profile.bundle_id);
    let prefs_name = format!("{}.plist", profile.bundle_id);
    ServiceCapabilities {
        has_app_sandbox: entitlement_bool(&profile.entitlements, "com.apple.security.app-sandbox"),
        has_get_task_allow: entitlement_bool(&profile.entitlements, "com.apple.security.get-task-allow"),
        has_disable_library_validation: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.cs.disable-library-validation",
        ),
        has_allow_dyld_env: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.cs.allow-dyld-environment-variables",
        ),
        has_allow_jit: entitlement_bool(&profile.entitlements, "com.apple.security.cs.allow-jit"),
        has_allow_unsigned_exec_mem: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.cs.allow-unsigned-executable-memory",
        ),
        has_network_client: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.network.client",
        ),
        has_downloads_rw: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.files.downloads.read-write",
        ),
        has_bookmarks_app_scope: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.files.bookmarks.app-scope",
        ),
        has_user_selected_read_only: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.files.user-selected.read-only",
        ),
        has_user_selected_read_write: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.files.user-selected.read-write",
        ),
        has_user_selected_executable: entitlement_bool(
            &profile.entitlements,
            "com.apple.security.files.user-selected.executable",
        ),
        home_dir: container_path(&base, &[]),
        tmp_dir: container_path(&base, &["tmp"]),
        downloads_dir: container_path(&base, &["Downloads"]),
        desktop_dir: container_path(&base, &["Desktop"]),
        documents_dir: container_path(&base, &["Documents"]),
        app_support_dir: container_path(&base, &["Library", "Application Support"]),
        caches_dir: container_path(&base, &["Library", "Caches"]),
        prefs_path_guess: container_path(&base, &["Library", "Preferences", &prefs_name]),
    }
}

fn matrix_groups() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("baseline", &["minimal"]),
        ("debug", &["minimal", "get-task-allow"]),
        ("inject", &["minimal", "fully_injectable"]),
    ]
}

fn resolve_matrix_group(name: &str) -> Option<&'static [&'static str]> {
    matrix_groups()
        .into_iter()
        .find(|(group, _)| *group == name)
        .map(|(_, profiles)| profiles)
}

fn emit_envelope<T: Serialize>(kind: &str, result: json_contract::JsonResult, data: &T) {
    if let Err(err) = json_contract::print_envelope(kind, result, data) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn write_envelope<T: Serialize>(
    path: &Path,
    kind: &str,
    result: json_contract::JsonResult,
    data: &T,
) -> Result<(), String> {
    json_contract::write_envelope(path, kind, result, data)
}

fn ensure_single_component(label: &str, value: &str) -> Result<(), String> {
    let mut components = Path::new(value).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(format!(
            "invalid {label} {value:?} (must be a single path component)"
        )),
    }
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        let home = env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        return Ok(PathBuf::from(home));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        let home = env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        return Ok(PathBuf::from(home).join(rest));
    }
    Ok(PathBuf::from(path))
}

fn default_bundle_output_dir() -> Result<PathBuf, String> {
    let home = env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("entitlement-jail")
        .join("evidence")
        .join("latest"))
}

fn default_matrix_output_dir(group_id: &str) -> Result<PathBuf, String> {
    let home = env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("entitlement-jail")
        .join("matrix")
        .join(group_id)
        .join("latest"))
}

fn ensure_clean_dir(path: &Path) -> Result<(), String> {
    if path == Path::new("/") {
        return Err("refusing to remove root directory".to_string());
    }
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing to remove symlink output path: {}",
                path.display()
            ));
        }
        if meta.is_file() {
            return Err(format!(
                "output path exists and is a file: {}",
                path.display()
            ));
        }
        if meta.is_dir() {
            std::fs::remove_dir_all(path).map_err(|e| {
                let mut msg = format!("failed to remove {}: {e}", path.display());
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    msg.push_str(" (permission denied; if sandboxed, choose a path under your container home)");
                }
                msg
            })?;
        }
    }
    std::fs::create_dir_all(path).map_err(|e| {
        let mut msg = format!("failed to create {}: {e}", path.display());
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            msg.push_str(" (permission denied; if sandboxed, choose a path under your container home)");
        }
        msg
    })
}

fn copy_evidence_file(src_dir: &Path, dst_dir: &Path, name: &str) -> Result<(), String> {
    let src = src_dir.join(name);
    let dst = dst_dir.join(name);
    if !src.exists() {
        return Err(format!("missing evidence file: {}", src.display()));
    }
    std::fs::copy(&src, &dst)
        .map_err(|e| format!("failed to copy {}: {e}", src.display()))?;
    Ok(())
}

fn resolve_app_root() -> PathBuf {
    let exe = env::current_exe().unwrap_or_else(|e| {
        eprintln!("current_exe() failed: {e}");
        std::process::exit(2);
    });
    evidence::app_root_from_exe(&exe).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(2);
    })
}

fn load_manifest(app_root: &Path) -> (evidence::EvidenceManifest, PathBuf) {
    let manifest_path = evidence::manifest_path_from_app_root(app_root);
    let manifest = evidence::load_manifest(&manifest_path).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(2);
    });
    (manifest, manifest_path)
}

fn load_profiles_manifest(app_root: &Path) -> (profiles::ProfilesManifest, PathBuf) {
    let profiles_path = profiles::profiles_path_from_app_root(app_root);
    let manifest = profiles::load_profiles(&profiles_path).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(2);
    });
    (manifest, profiles_path)
}

fn run_xpc_probe(service_id: &str, probe_id: &str, probe_args: &[&str]) -> Result<(String, i32, String), String> {
    let cmd_path = resolve_contents_macos_tool("xpc-probe-client")?;
    let mut cmd = Command::new(&cmd_path);
    cmd.arg("run").arg(service_id).arg(probe_id).args(probe_args);
    let output = cmd
        .output()
        .map_err(|e| format!("spawn failed for {}: {e}", cmd_path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(1);
    Ok((stdout, exit_code, stderr))
}

fn parse_probe_response(stdout: &str) -> Result<(Option<i64>, Option<String>, Option<String>), String> {
    let value: serde_json::Value =
        serde_json::from_str(stdout).map_err(|e| format!("failed to parse probe JSON: {e}"))?;
    let result = value
        .get("result")
        .ok_or_else(|| "missing result in probe JSON".to_string())?;
    let rc = result.get("rc").and_then(|v| v.as_i64());
    let normalized_outcome = result
        .get("normalized_outcome")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let error = result
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok((rc, normalized_outcome, error))
}

fn build_health_check_report(
    manifest: &profiles::ProfilesManifest,
    profiles_path: &Path,
    profile_filter: Option<&str>,
) -> Result<HealthCheckReport, String> {
    let mut selected: Vec<profiles::ProfileEntry> = Vec::new();
    if let Some(filter) = profile_filter {
        let profile = profiles::find_profile(manifest, filter)
            .ok_or_else(|| format!("unknown profile: {filter}"))?;
        if profile.kind != "probe" {
            return Err(format!(
                "health-check only supports probe profiles (profile {} is kind={})",
                profile.profile_id, profile.kind
            ));
        }
        selected.push(profile.clone());
    } else {
        for profile in profiles::filter_profiles(manifest, Some("probe")) {
            selected.push(profile.clone());
        }
    }

    let probe_plan: [(&str, &[&str]); 3] = [
        ("capabilities_snapshot", &[]),
        ("world_shape", &[]),
        ("fs_op", &["--op", "stat", "--path-class", "tmp"]),
    ];

    let mut profile_reports = Vec::new();
    for profile in selected {
        let mut probes = Vec::new();
        let mut profile_ok = true;
        for (probe_id, probe_args) in probe_plan {
            let (stdout, exit_code, stderr) =
                match run_xpc_probe(&profile.bundle_id, probe_id, probe_args) {
                    Ok(result) => result,
                    Err(err) => {
                        profile_ok = false;
                        probes.push(HealthProbeResult {
                            probe_id: probe_id.to_string(),
                            rc: None,
                            normalized_outcome: None,
                            error: Some(err),
                            exit_code: 127,
                            parse_error: None,
                            stderr: None,
                        });
                        continue;
                    }
                };

            let mut parse_error = None;
            let mut rc = None;
            let mut outcome = None;
            let mut error = None;
            match parse_probe_response(&stdout) {
                Ok((parsed_rc, parsed_outcome, parsed_error)) => {
                    rc = parsed_rc;
                    outcome = parsed_outcome;
                    error = parsed_error;
                }
                Err(err) => {
                    parse_error = Some(err);
                }
            }

            let ok = exit_code == 0 && parse_error.is_none() && rc == Some(0);
            if !ok {
                profile_ok = false;
            }

            probes.push(HealthProbeResult {
                probe_id: probe_id.to_string(),
                rc,
                normalized_outcome: outcome,
                error,
                exit_code,
                parse_error,
                stderr: if stderr.is_empty() { None } else { Some(stderr) },
            });
        }

        profile_reports.push(HealthProfileResult {
            profile_id: profile.profile_id.clone(),
            bundle_id: profile.bundle_id.clone(),
            kind: profile.kind.clone(),
            ok: profile_ok,
            probes,
        });
    }

    let ok = profile_reports.iter().all(|profile| profile.ok);
    Ok(HealthCheckReport {
        ok,
        profiles_path: profiles_path.display().to_string(),
        profiles: profile_reports,
    })
}

fn build_inspect_entry(entry: &evidence::EvidenceEntry, abs_path: &Path) -> InspectEntry {
    InspectEntry {
        id: entry.id.clone(),
        kind: entry.kind.clone(),
        bundle_id: entry.bundle_id.clone(),
        rel_path: entry.rel_path.clone(),
        abs_path: abs_path.display().to_string(),
        sha256: entry.sha256.clone(),
        lc_uuid: entry.lc_uuid.clone(),
        entitlements: entry.entitlements.clone(),
        entitlements_error: entry.entitlements_error.clone(),
    }
}

fn is_allowed_system_path(cmd_path: &Path) -> bool {
    let allowed_prefixes = [
        Path::new("/bin"),
        Path::new("/usr/bin"),
        Path::new("/sbin"),
        Path::new("/usr/sbin"),
        Path::new("/usr/libexec"),
        Path::new("/System/Library"),
    ];
    allowed_prefixes.iter().any(|prefix| cmd_path.starts_with(prefix))
}

fn ensure_executable_file(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("expected executable at {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("expected file at {}", path.display()));
    }
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(format!("expected executable file at {}", path.display()));
    }
    Ok(())
}

fn embedded_search_paths() -> Result<Vec<PathBuf>, String> {
    let exe = env::current_exe().map_err(|e| format!("current_exe() failed: {e}"))?;
    let contents_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| format!("unexpected executable location: {}", exe.display()))?;

    Ok(vec![
        contents_dir.join("Helpers"),
        contents_dir.join("Helpers").join("Probes"),
    ])
}

fn resolve_contents_macos_tool(tool_name: &str) -> Result<PathBuf, String> {
    validate_tool_name(tool_name)?;
    let exe = env::current_exe().map_err(|e| format!("current_exe() failed: {e}"))?;
    let contents_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| format!("unexpected executable location: {}", exe.display()))?;

    let candidate = contents_dir.join("MacOS").join(tool_name);
    if candidate.exists() {
        return Ok(candidate);
    }

    Err(format!(
        "embedded tool not found in Contents/MacOS: {tool_name:?} (expected: {})",
        candidate.display()
    ))
}

fn validate_tool_name(tool_name: &str) -> Result<(), String> {
    let mut components = Path::new(tool_name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(format!(
            "invalid tool name {tool_name:?} (must be a single path component)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_platform_system_paths() {
        assert!(is_allowed_system_path(Path::new("/bin/ls")));
        assert!(is_allowed_system_path(Path::new("/usr/bin/env")));
        assert!(is_allowed_system_path(Path::new("/System/Library/CoreServices")));
        assert!(!is_allowed_system_path(Path::new("/usr/local/bin/ls")));
        assert!(!is_allowed_system_path(Path::new("/tmp/ls")));
        assert!(!is_allowed_system_path(Path::new("relative/path")));
    }

    #[test]
    fn validates_tool_name_single_component() {
        assert!(validate_tool_name("tool").is_ok());
        assert!(validate_tool_name("xpc-probe-client").is_ok());
    }

    #[test]
    fn rejects_tool_name_traversal_or_subpaths() {
        assert!(validate_tool_name("../tool").is_err());
        assert!(validate_tool_name("./tool").is_err());
        assert!(validate_tool_name("tools/tool").is_err());
        assert!(validate_tool_name("tool/../x").is_err());
    }
}

fn resolve_embedded_tool(tool_name: &str) -> Result<PathBuf, String> {
    validate_tool_name(tool_name)?;
    let search_paths = embedded_search_paths()?;

    for dir in search_paths {
        let candidate = dir.join(tool_name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "embedded tool not found: {tool_name:?} (searched: {})",
        embedded_search_paths()?
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn exit_like_child(status: std::process::ExitStatus) -> ! {
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status.signal() {
        std::process::exit(128 + signal);
    }
    std::process::exit(128);
}

fn run_and_wait(cmd_path: PathBuf, cmd_args: Vec<OsString>) -> ! {
    let mut cmd = Command::new(&cmd_path);
    cmd.args(cmd_args);

    let status = match cmd.status() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("spawn failed for {}: {err}", cmd_path.display());
            std::process::exit(127);
        }
    };

    exit_like_child(status)
}

fn main() {
    if env::var("EJ_DEBUG_DLOPEN").ok().as_deref() == Some("1") {
        debug_entitlements_probe::try_dlopen_external_library();
    }

    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let subcommand = args[0].to_str();
    match subcommand {
        Some("help") | Some("-h") | Some("--help") => {
            print_usage();
            return;
        }
        Some("verify-evidence") => {
            let app_root = resolve_app_root();
            let (manifest, manifest_path) = load_manifest(&app_root);
            let report = evidence::verify_manifest(&manifest, &app_root, &manifest_path);
            let ok = report.ok;
            emit_envelope("verify_evidence_report", json_contract::JsonResult::from_ok(ok), &report);
            std::process::exit(if ok { 0 } else { 3 });
        }
        Some("inspect-macho") => {
            let selector = match args.get(1).and_then(|s| s.to_str()) {
                Some("-h") | Some("--help") => {
                    print_usage();
                    std::process::exit(0);
                }
                Some(s) => s,
                None => {
                    eprintln!("missing selector for inspect-macho\n");
                    print_usage();
                    std::process::exit(2);
                }
            };

            let app_root = resolve_app_root();
            let (manifest, manifest_path) = load_manifest(&app_root);

            let entry = if selector == "main" {
                let rel = manifest.app_binary_rel_path.clone().unwrap_or_else(|| {
                    eprintln!("manifest is missing app_binary_rel_path");
                    std::process::exit(2);
                });
                let abs_path = app_root.join(&rel);
                InspectEntry {
                    id: "main".to_string(),
                    kind: "main".to_string(),
                    bundle_id: manifest.app_bundle_id.clone(),
                    rel_path: rel,
                    abs_path: abs_path.display().to_string(),
                    sha256: None,
                    lc_uuid: None,
                    entitlements: manifest.app_entitlements.clone(),
                    entitlements_error: None,
                }
            } else {
                let mut entry = evidence::find_entry_by_id(&manifest, selector);
                if entry.is_none() {
                    entry = evidence::find_entry_by_rel_path(&manifest, selector);
                }
                if entry.is_none() {
                    let selector_path = Path::new(selector);
                    if selector_path.is_absolute() {
                        if let Some(rel) = evidence::rel_path_from_absolute(&app_root, selector_path) {
                            entry = evidence::find_entry_by_rel_path(&manifest, &rel);
                        }
                    }
                }
                let entry = entry.unwrap_or_else(|| {
                    eprintln!("unknown entry for selector: {selector}");
                    std::process::exit(2);
                });
                let abs_path = app_root.join(&entry.rel_path);
                build_inspect_entry(entry, &abs_path)
            };

            let report = InspectReport {
                selector: selector.to_string(),
                app_root: app_root.display().to_string(),
                manifest_path: manifest_path.display().to_string(),
                entry,
            };
            emit_envelope("inspect_macho_report", json_contract::JsonResult::from_ok(true), &report);
            return;
        }
        Some("list-profiles") => {
            let app_root = resolve_app_root();
            let (manifest, profiles_path) = load_profiles_manifest(&app_root);
            let mut profiles = manifest.profiles.clone();
            profiles.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
            let report = ProfilesReport {
                profiles_path: profiles_path.display().to_string(),
                generated_at: manifest.generated_at,
                profiles,
            };
            emit_envelope("profiles_report", json_contract::JsonResult::from_ok(true), &report);
            return;
        }
        Some("list-services") => {
            let app_root = resolve_app_root();
            let (manifest, profiles_path) = load_profiles_manifest(&app_root);
            let mut services = manifest.profiles.clone();
            services.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
            let report = ServicesReport {
                profiles_path: profiles_path.display().to_string(),
                generated_at: manifest.generated_at,
                services,
            };
            emit_envelope("services_report", json_contract::JsonResult::from_ok(true), &report);
            return;
        }
        Some("show-profile") => {
            let selector = match args.get(1).and_then(|s| s.to_str()) {
                Some(s) => s,
                None => {
                    eprintln!("missing selector for show-profile\n");
                    print_usage();
                    std::process::exit(2);
                }
            };
            let app_root = resolve_app_root();
            let (manifest, profiles_path) = load_profiles_manifest(&app_root);
            let profile = profiles::find_profile(&manifest, selector).unwrap_or_else(|| {
                eprintln!("unknown profile: {selector}");
                std::process::exit(2);
            });
            let report = ProfileReport {
                profiles_path: profiles_path.display().to_string(),
                profile: profile.clone(),
            };
            emit_envelope("profile_report", json_contract::JsonResult::from_ok(true), &report);
            return;
        }
        Some("describe-service") => {
            let selector = match args.get(1).and_then(|s| s.to_str()) {
                Some(s) => s,
                None => {
                    eprintln!("missing selector for describe-service\n");
                    print_usage();
                    std::process::exit(2);
                }
            };
            let app_root = resolve_app_root();
            let (manifest, _) = load_profiles_manifest(&app_root);
            let profile = profiles::find_profile(&manifest, selector).unwrap_or_else(|| {
                eprintln!("unknown service: {selector}");
                std::process::exit(2);
            });
            let report = DescribeServiceReport {
                service: profile.clone(),
                capabilities_source: "static".to_string(),
                capabilities: build_static_capabilities(profile),
            };
            emit_envelope("describe_service_report", json_contract::JsonResult::from_ok(true), &report);
            return;
        }
        Some("health-check") => {
            let mut profile_filter: Option<String> = None;
            let mut idx = 1;
            while idx < args.len() {
                match args.get(idx).and_then(|s| s.to_str()) {
                    Some("--profile") => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| {
                                "missing value for --profile".to_string()
                            });
                        match value {
                            Ok(v) => profile_filter = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    Some("-h") | Some("--help") => {
                        print_usage();
                        return;
                    }
                    Some(other) => {
                        eprintln!("unknown argument for health-check: {other}");
                        print_usage();
                        std::process::exit(2);
                    }
                    None => break,
                }
            }

            let app_root = resolve_app_root();
            let (manifest, profiles_path) = load_profiles_manifest(&app_root);
            let report = match build_health_check_report(
                &manifest,
                &profiles_path,
                profile_filter.as_deref(),
            ) {
                Ok(report) => report,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            };
            let ok = report.ok;
            emit_envelope(
                "health_check_report",
                json_contract::JsonResult::from_ok(ok),
                &report,
            );
            std::process::exit(if ok { 0 } else { 3 });
        }
        Some("bundle-evidence") => {
            let mut out_arg: Option<String> = None;
            let mut include_health_check = false;
            let mut ack_risk: Option<String> = None;
            let mut idx = 1;
            while idx < args.len() {
                match args.get(idx).and_then(|s| s.to_str()) {
                    Some("-h") | Some("--help") => {
                        print_usage();
                        return;
                    }
                    Some("--out") => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| "missing value for --out".to_string());
                        match value {
                            Ok(v) => out_arg = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    Some("--include-health-check") => {
                        include_health_check = true;
                        idx += 1;
                    }
                    Some("--ack-risk") => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| "missing value for --ack-risk".to_string());
                        match value {
                            Ok(v) => ack_risk = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    Some(other) => {
                        eprintln!("unknown argument for bundle-evidence: {other}");
                        print_usage();
                        std::process::exit(2);
                    }
                    None => break,
                }
            }

            let out_dir = match out_arg {
                Some(value) => match expand_tilde_path(&value) {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                },
                None => match default_bundle_output_dir() {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                },
            };

            if let Err(err) = ensure_clean_dir(&out_dir) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let app_root = resolve_app_root();
            let (manifest, manifest_path) = load_manifest(&app_root);
            let (profiles_manifest, profiles_path) = load_profiles_manifest(&app_root);

            let evidence_src = app_root.join("Contents").join("Resources").join("Evidence");
            let evidence_out = out_dir.join("Evidence");
            if let Err(err) = std::fs::create_dir_all(&evidence_out) {
                eprintln!("failed to create {}: {err}", evidence_out.display());
                std::process::exit(2);
            }
            if let Err(err) = copy_evidence_file(&evidence_src, &evidence_out, "manifest.json") {
                eprintln!("{err}");
                std::process::exit(2);
            }
            if let Err(err) = copy_evidence_file(&evidence_src, &evidence_out, "symbols.json") {
                eprintln!("{err}");
                std::process::exit(2);
            }
            if let Err(err) = copy_evidence_file(&evidence_src, &evidence_out, "profiles.json") {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let verify_report = evidence::verify_manifest(&manifest, &app_root, &manifest_path);
            let verify_path = out_dir.join("verify-evidence.json");
            if let Err(err) = write_envelope(
                &verify_path,
                "verify_evidence_report",
                json_contract::JsonResult::from_ok(verify_report.ok),
                &verify_report,
            ) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let mut profiles_sorted = profiles_manifest.profiles.clone();
            profiles_sorted.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
            let list_report = ProfilesReport {
                profiles_path: profiles_path.display().to_string(),
                generated_at: profiles_manifest.generated_at.clone(),
                profiles: profiles_sorted.clone(),
            };
            let list_path = out_dir.join("list-profiles.json");
            if let Err(err) = write_envelope(
                &list_path,
                "profiles_report",
                json_contract::JsonResult::from_ok(true),
                &list_report,
            ) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let profiles_out_dir = out_dir.join("profiles");
            if let Err(err) = std::fs::create_dir_all(&profiles_out_dir) {
                eprintln!("failed to create {}: {err}", profiles_out_dir.display());
                std::process::exit(2);
            }

            let mut included_profiles = Vec::new();
            let mut skipped_profiles = Vec::new();
            for profile in profiles_sorted {
                let tier = profile.risk_tier.unwrap_or(2);
                let ack_ok = ack_risk
                    .as_ref()
                    .map(|ack| ack == &profile.profile_id || ack == &profile.bundle_id)
                    .unwrap_or(false);
                if tier >= 2 && !ack_ok {
                    skipped_profiles.push(BundleProfileSkip {
                        profile_id: profile.profile_id.clone(),
                        bundle_id: profile.bundle_id.clone(),
                        reason: "tier2_requires_ack".to_string(),
                        risk_tier: profile.risk_tier,
                        risk_reasons: profile.risk_reasons.clone(),
                    });
                    continue;
                }
                if let Err(err) = ensure_single_component("profile id", &profile.profile_id) {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
                let report = ProfileReport {
                    profiles_path: profiles_path.display().to_string(),
                    profile: profile.clone(),
                };
                let out_path = profiles_out_dir.join(format!("{}.json", profile.profile_id));
                if let Err(err) = write_envelope(
                    &out_path,
                    "profile_report",
                    json_contract::JsonResult::from_ok(true),
                    &report,
                ) {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
                included_profiles.push(profile.profile_id.clone());
            }

            let mut health_ok = None;
            if include_health_check {
                let report = match build_health_check_report(
                    &profiles_manifest,
                    &profiles_path,
                    Some("minimal"),
                ) {
                    Ok(report) => report,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                };
                health_ok = Some(report.ok);
                let health_path = out_dir.join("health-check.json");
                if let Err(err) = write_envelope(
                    &health_path,
                    "health_check_report",
                    json_contract::JsonResult::from_ok(report.ok),
                    &report,
                ) {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let args_list: Vec<String> = env::args().collect();
            let ack_list = ack_risk.clone().map(|v| vec![v]).unwrap_or_default();
            let meta = BundleMeta {
                generated_at_unix_ms: now,
                app_root: app_root.display().to_string(),
                app_bundle_id: manifest.app_bundle_id.clone(),
                output_dir: out_dir.display().to_string(),
                args: args_list,
                include_health_check,
                ack_risk: ack_list,
                verify_ok: verify_report.ok,
                health_ok,
                profiles_included: included_profiles,
                profiles_skipped: skipped_profiles,
            };
            let meta_path = out_dir.join("bundle_meta.json");
            let ok = verify_report.ok && health_ok.unwrap_or(true);
            if let Err(err) = write_envelope(
                &meta_path,
                "bundle_evidence_report",
                json_contract::JsonResult::from_ok(ok),
                &meta,
            ) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let mut exit_code = 0;
            if !verify_report.ok {
                exit_code = 3;
            }
            if let Some(ok) = health_ok {
                if !ok {
                    exit_code = 3;
                }
            }
            emit_envelope(
                "bundle_evidence_report",
                json_contract::JsonResult::from_ok(ok),
                &meta,
            );
            std::process::exit(exit_code);
        }
        Some("run-matrix") => {
            let mut group_arg: Option<String> = None;
            let mut out_arg: Option<String> = None;
            let mut ack_risk: Option<String> = None;
            let mut idx = 1;
            while idx < args.len() {
                let arg = match args.get(idx).and_then(|s| s.to_str()) {
                    Some(value) => value,
                    None => break,
                };
                if arg == "--" {
                    idx += 1;
                    break;
                }
                if !arg.starts_with('-') {
                    break;
                }
                match arg {
                    "-h" | "--help" => {
                        print_usage();
                        return;
                    }
                    "--group" => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| "missing value for --group".to_string());
                        match value {
                            Ok(v) => group_arg = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    "--out" => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| "missing value for --out".to_string());
                        match value {
                            Ok(v) => out_arg = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    "--ack-risk" => {
                        let value = args
                            .get(idx + 1)
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| "missing value for --ack-risk".to_string());
                        match value {
                            Ok(v) => ack_risk = Some(v.to_string()),
                            Err(err) => {
                                eprintln!("{err}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                        idx += 2;
                    }
                    other => {
                        eprintln!("unknown argument for run-matrix: {other}");
                        print_usage();
                        std::process::exit(2);
                    }
                }
            }

            let group_id = match group_arg {
                Some(group) => group,
                None => {
                    let names = matrix_groups()
                        .into_iter()
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>()
                        .join(", ");
                    eprintln!("missing --group (available: {names})");
                    print_usage();
                    std::process::exit(2);
                }
            };
            if let Err(err) = ensure_single_component("group id", &group_id) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let probe_id = match args.get(idx).and_then(|s| s.to_str()) {
                Some(probe) => probe.to_string(),
                None => {
                    eprintln!("missing probe id for run-matrix");
                    print_usage();
                    std::process::exit(2);
                }
            };
            let probe_args: Vec<String> = args
                .iter()
                .skip(idx + 1)
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let probe_arg_refs: Vec<&str> = probe_args.iter().map(|s| s.as_str()).collect();

            let group_profiles = match resolve_matrix_group(&group_id) {
                Some(profiles) => profiles,
                None => {
                    let names = matrix_groups()
                        .into_iter()
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>()
                        .join(", ");
                    eprintln!("unknown group {group_id} (available: {names})");
                    std::process::exit(2);
                }
            };

            let out_dir = match out_arg {
                Some(value) => match expand_tilde_path(&value) {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                },
                None => match default_matrix_output_dir(&group_id) {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                },
            };

            if let Err(err) = ensure_clean_dir(&out_dir) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let app_root = resolve_app_root();
            let (profiles_manifest, _) = load_profiles_manifest(&app_root);

            let mut runs = Vec::new();
            let mut skipped = Vec::new();
            let group_profiles_vec: Vec<String> =
                group_profiles.iter().map(|s| s.to_string()).collect();

            for profile_id in group_profiles {
                let profile = profiles::find_profile(&profiles_manifest, profile_id).unwrap_or_else(|| {
                    eprintln!("missing profile in group {group_id}: {profile_id}");
                    std::process::exit(2);
                });
                if profile.kind != "probe" {
                    eprintln!(
                        "run-matrix only supports probe profiles (profile {} is kind={})",
                        profile.profile_id, profile.kind
                    );
                    std::process::exit(2);
                }

                let tier = profile.risk_tier.unwrap_or(2);
                let ack_ok = ack_risk
                    .as_ref()
                    .map(|ack| ack == &profile.profile_id || ack == &profile.bundle_id)
                    .unwrap_or(false);
                if tier >= 2 && !ack_ok {
                    skipped.push(MatrixSkip {
                        profile_id: profile.profile_id.clone(),
                        bundle_id: profile.bundle_id.clone(),
                        reason: "tier2_requires_ack".to_string(),
                        risk_tier: profile.risk_tier,
                        risk_reasons: profile.risk_reasons.clone(),
                    });
                    continue;
                }

                let start = std::time::Instant::now();
                let result = run_xpc_probe(&profile.bundle_id, &probe_id, &probe_arg_refs);
                let elapsed = start.elapsed();

                let (stdout, exit_code, stderr) = match result {
                    Ok(v) => v,
                    Err(err) => {
                        runs.push(MatrixRun {
                            profile_id: profile.profile_id.clone(),
                            bundle_id: profile.bundle_id.clone(),
                            label: profile.label.clone(),
                            risk_tier: profile.risk_tier,
                            risk_reasons: profile.risk_reasons.clone(),
                            exit_code: 127,
                            duration_ms: elapsed.as_millis(),
                            rc: None,
                            normalized_outcome: None,
                            error: Some(err),
                            parse_error: None,
                            response: None,
                        });
                        continue;
                    }
                };

                let mut parse_error = None;
                let mut rc = None;
                let mut outcome = None;
                let mut error = None;
                let mut response_json = None;
                match serde_json::from_str::<serde_json::Value>(&stdout) {
                    Ok(value) => {
                        if let Some(result) = value.get("result") {
                            rc = result.get("rc").and_then(|v| v.as_i64());
                            outcome = result
                                .get("normalized_outcome")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            error = result
                                .get("error")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        } else {
                            parse_error = Some("missing result in probe JSON".to_string());
                        }
                        response_json = Some(value);
                    }
                    Err(err) => {
                        parse_error = Some(format!("failed to parse probe JSON: {err}"));
                    }
                }

                if !stderr.is_empty() && error.is_none() {
                    error = Some(stderr);
                }

                runs.push(MatrixRun {
                    profile_id: profile.profile_id.clone(),
                    bundle_id: profile.bundle_id.clone(),
                    label: profile.label.clone(),
                    risk_tier: profile.risk_tier,
                    risk_reasons: profile.risk_reasons.clone(),
                    exit_code,
                    duration_ms: elapsed.as_millis(),
                    rc,
                    normalized_outcome: outcome,
                    error,
                    parse_error,
                    response: response_json,
                });
            }

            let generated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();

            let report = RunMatrixReport {
                group_id: group_id.clone(),
                probe_id: probe_id.clone(),
                probe_argv: probe_args.clone(),
                generated_at_unix_ms: generated,
                output_dir: out_dir.display().to_string(),
                profiles: group_profiles_vec.clone(),
                runs: runs.clone(),
                skipped: skipped.clone(),
            };

            let json_path = out_dir.join("run-matrix.json");
            if let Err(err) = write_envelope(
                &json_path,
                "run_matrix_report",
                json_contract::JsonResult::from_ok(true),
                &report,
            ) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let mut lines = Vec::new();
            lines.push("profile_id\tbundle_id\texit_code\trc\tnormalized_outcome\tduration_ms\tnote".to_string());
            for run in &runs {
                let note = run
                    .parse_error
                    .clone()
                    .unwrap_or_else(|| "".to_string());
                lines.push(format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    run.profile_id,
                    run.bundle_id,
                    run.exit_code,
                    run.rc.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                    run.normalized_outcome.clone().unwrap_or_else(|| "-".to_string()),
                    run.duration_ms,
                    note,
                ));
            }
            for skip in &skipped {
                lines.push(format!(
                    "{}\t{}\t-\t-\t-\t-\tskipped: {}",
                    skip.profile_id, skip.bundle_id, skip.reason
                ));
            }

            let table_path = out_dir.join("run-matrix.table.txt");
            if let Err(err) = std::fs::write(&table_path, lines.join("\n")) {
                eprintln!("failed to write {}: {err}", table_path.display());
                std::process::exit(2);
            }

            emit_envelope(
                "run_matrix_report",
                json_contract::JsonResult::from_ok(true),
                &report,
            );
            std::process::exit(0);
        }
        Some("run-system") => {
            let cmd_path = match args.get(1) {
                Some(p) => PathBuf::from(p),
                None => {
                    print_usage();
                    std::process::exit(2);
                }
            };
            if !cmd_path.is_absolute() || !is_allowed_system_path(&cmd_path) {
                eprintln!(
                    "refusing to exec non-platform path: {}\n\nmacOS App Sandbox generally denies process-exec* from writable locations (including the app container).\nUse `run-system` with an in-place platform binary, or embed/sign your probe and use `run-embedded`.",
                    cmd_path.display()
                );
                std::process::exit(2);
            }
            if let Err(err) = ensure_executable_file(&cmd_path) {
                eprintln!("{err}");
                std::process::exit(2);
            }
            run_and_wait(cmd_path, args[2..].to_vec());
        }
        Some("run-embedded") => {
            let tool_name = match args.get(1).and_then(|s| s.to_str()) {
                Some(s) => s,
                None => {
                    eprintln!("missing or non-utf8 tool name\n");
                    print_usage();
                    std::process::exit(2);
                }
            };
            let cmd_path = match resolve_embedded_tool(tool_name) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}\n");
                    print_usage();
                    std::process::exit(2);
                }
            };
            if let Err(err) = ensure_executable_file(&cmd_path) {
                eprintln!("{err}");
                std::process::exit(2);
            }
            run_and_wait(cmd_path, args[2..].to_vec());
        }
        Some("xpc") => {
            let mode = match args.get(1).and_then(|s| s.to_str()) {
                Some("-h") | Some("--help") => {
                    print_usage();
                    return;
                }
                Some("run") => "run",
                Some("session") => "session",
                Some(other) => {
                    eprintln!("unknown xpc subcommand: {other}");
                    print_usage();
                    std::process::exit(2);
                }
                None => {
                    eprintln!("missing xpc subcommand (expected: run|session)");
                    print_usage();
                    std::process::exit(2);
                }
            };

            let cmd_path = match resolve_contents_macos_tool("xpc-probe-client") {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}\n");
                    eprintln!("note: xpc commands require the embedded `xpc-probe-client` tool under Contents/MacOS.");
                    std::process::exit(2);
                }
            };
            if let Err(err) = ensure_executable_file(&cmd_path) {
                eprintln!("{err}");
                std::process::exit(2);
            }

            let app_root = resolve_app_root();
            let (profiles_manifest, _) = load_profiles_manifest(&app_root);

            match mode {
                "run" => {
                    let mut profile_arg: Option<String> = None;
                    let mut service_arg: Option<String> = None;
                    let mut ack_risk: Option<String> = None;
                    let mut plan_id: Option<String> = None;
                    let mut row_id: Option<String> = None;
                    let mut correlation_id: Option<String> = None;

                    let mut idx = 2usize;
                    while idx < args.len() {
                        let arg = match args.get(idx).and_then(|s| s.to_str()) {
                            Some(value) => value,
                            None => break,
                        };
                        if arg == "--" {
                            idx += 1;
                            break;
                        }
                        if !arg.starts_with('-') {
                            break;
                        }
                        match arg {
                            "-h" | "--help" => {
                                print_usage();
                                return;
                            }
                            "--profile" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --profile".to_string());
                                match value {
                                    Ok(v) => {
                                        if profile_arg.is_some() {
                                            eprintln!("--profile specified multiple times");
                                            print_usage();
                                            std::process::exit(2);
                                        }
                                        profile_arg = Some(v.to_string());
                                    }
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--service" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --service".to_string());
                                match value {
                                    Ok(v) => {
                                        if service_arg.is_some() {
                                            eprintln!("--service specified multiple times");
                                            print_usage();
                                            std::process::exit(2);
                                        }
                                        service_arg = Some(v.to_string());
                                    }
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--ack-risk" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --ack-risk".to_string());
                                match value {
                                    Ok(v) => {
                                        if ack_risk.is_some() {
                                            eprintln!("--ack-risk specified multiple times");
                                            print_usage();
                                            std::process::exit(2);
                                        }
                                        ack_risk = Some(v.to_string());
                                    }
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--plan-id" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --plan-id".to_string());
                                match value {
                                    Ok(v) => plan_id = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--row-id" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --row-id".to_string());
                                match value {
                                    Ok(v) => row_id = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--correlation-id" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value =
                                    value.ok_or_else(|| "missing value for --correlation-id".to_string());
                                match value {
                                    Ok(v) => correlation_id = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            other => {
                                eprintln!("unknown argument for xpc run: {other}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                    }

                    if profile_arg.is_some() && service_arg.is_some() {
                        eprintln!("--profile cannot be combined with --service");
                        print_usage();
                        std::process::exit(2);
                    }

                    let target_profile = profile_arg
                        .as_ref()
                        .and_then(|id| profiles::find_profile(&profiles_manifest, id));

                    let service_id = if let Some(profile) = target_profile {
                        if profile.kind != "probe" {
                            eprintln!(
                                "profile is not a probe service: {} (kind={})",
                                profile.profile_id, profile.kind
                            );
                            std::process::exit(2);
                        }
                        profile.bundle_id.clone()
                    } else if let Some(service_id) = service_arg.as_ref() {
                        service_id.clone()
                    } else {
                        eprintln!("missing --profile or --service");
                        print_usage();
                        std::process::exit(2);
                    };

                    let profile = target_profile.or_else(|| {
                        let profile = resolve_profile_by_bundle_id(&profiles_manifest, &service_id);
                        if let Some(profile) = profile {
                            if profile.kind != "probe" {
                                eprintln!(
                                    "service is not a probe profile: {} (kind={})",
                                    profile.profile_id, profile.kind
                                );
                                std::process::exit(2);
                            }
                        }
                        profile
                    });

                    let (gate, reasons, label) = risk_gate_for_profile(profile);
                    let require_ack = matches!(gate, RiskGate::RequireAck);
                    let warn_only = matches!(gate, RiskGate::Warn);

                    if warn_only {
                        let profile_id = profile.map(|p| p.profile_id.clone());
                        let name = label
                            .clone()
                            .or_else(|| profile_id.clone())
                            .unwrap_or_else(|| service_id.clone());
                        if reasons.is_empty() {
                            eprintln!("warning: profile {name} is tier 1 (some concern)");
                        } else {
                            eprintln!(
                                "warning: profile {name} is tier 1 (reasons: {})",
                                reasons.join(", ")
                            );
                        }
                    }

                    if require_ack {
                        let profile_id = profile.map(|p| p.profile_id.clone());
                        let ack_ok = ack_risk
                            .as_ref()
                            .map(|ack| {
                                ack == &service_id
                                    || profile_id
                                        .as_ref()
                                        .map(|id| ack == id)
                                        .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        if !ack_ok {
                            let name = label
                                .or_else(|| profile_id.clone())
                                .unwrap_or_else(|| service_id.clone());
                            let ack_hint = profile_id.unwrap_or_else(|| service_id.clone());
                            let msg = if reasons.is_empty() {
                                format!("profile {name} is tier 2 (high concern); re-run with --ack-risk {ack_hint}")
                            } else {
                                format!(
                                    "profile {name} is tier 2 (reasons: {}); re-run with --ack-risk {ack_hint}",
                                    reasons.join(", ")
                                )
                            };
                            eprintln!("{msg}");
                            std::process::exit(2);
                        }
                    }

                    let probe_id = match args.get(idx).and_then(|s| s.to_str()) {
                        Some(probe) => probe.to_string(),
                        None => {
                            eprintln!("missing probe id for xpc run");
                            print_usage();
                            std::process::exit(2);
                        }
                    };
                    let probe_args: Vec<OsString> = args.iter().skip(idx + 1).cloned().collect();

                    let mut forward_args: Vec<OsString> = Vec::new();
                    forward_args.push(OsString::from("run"));
                    if let Some(plan_id) = plan_id {
                        forward_args.push(OsString::from("--plan-id"));
                        forward_args.push(OsString::from(plan_id));
                    }
                    if let Some(row_id) = row_id {
                        forward_args.push(OsString::from("--row-id"));
                        forward_args.push(OsString::from(row_id));
                    }
                    if let Some(correlation_id) = correlation_id {
                        forward_args.push(OsString::from("--correlation-id"));
                        forward_args.push(OsString::from(correlation_id));
                    }
                    forward_args.push(OsString::from(service_id));
                    forward_args.push(OsString::from(probe_id));
                    forward_args.extend(probe_args);

                    run_and_wait(cmd_path, forward_args);
                }
                "session" => {
                    let mut profile_arg: Option<String> = None;
                    let mut service_arg: Option<String> = None;
                    let mut ack_risk: Option<String> = None;
                    let mut plan_id: Option<String> = None;
                    let mut correlation_id: Option<String> = None;
                    let mut wait_spec: Option<String> = None;
                    let mut wait_timeout_ms: Option<String> = None;
                    let mut wait_interval_ms: Option<String> = None;
                    let mut xpc_timeout_ms: Option<String> = None;

                    let mut idx = 2usize;
                    while idx < args.len() {
                        let arg = match args.get(idx).and_then(|s| s.to_str()) {
                            Some(value) => value,
                            None => break,
                        };
                        if arg == "--" {
                            idx += 1;
                            break;
                        }
                        if !arg.starts_with('-') {
                            break;
                        }
                        match arg {
                            "-h" | "--help" => {
                                print_usage();
                                return;
                            }
                            "--profile" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --profile".to_string());
                                match value {
                                    Ok(v) => profile_arg = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--service" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --service".to_string());
                                match value {
                                    Ok(v) => service_arg = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--ack-risk" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --ack-risk".to_string());
                                match value {
                                    Ok(v) => ack_risk = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--plan-id" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --plan-id".to_string());
                                match value {
                                    Ok(v) => plan_id = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--correlation-id" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value =
                                    value.ok_or_else(|| "missing value for --correlation-id".to_string());
                                match value {
                                    Ok(v) => correlation_id = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--wait" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value = value.ok_or_else(|| "missing value for --wait".to_string());
                                match value {
                                    Ok(v) => wait_spec = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--wait-timeout-ms" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value =
                                    value.ok_or_else(|| "missing value for --wait-timeout-ms".to_string());
                                match value {
                                    Ok(v) => wait_timeout_ms = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--wait-interval-ms" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value =
                                    value.ok_or_else(|| "missing value for --wait-interval-ms".to_string());
                                match value {
                                    Ok(v) => wait_interval_ms = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            "--xpc-timeout-ms" => {
                                let value = args.get(idx + 1).and_then(|s| s.to_str());
                                let value =
                                    value.ok_or_else(|| "missing value for --xpc-timeout-ms".to_string());
                                match value {
                                    Ok(v) => xpc_timeout_ms = Some(v.to_string()),
                                    Err(err) => {
                                        eprintln!("{err}");
                                        print_usage();
                                        std::process::exit(2);
                                    }
                                }
                                idx += 2;
                            }
                            other => {
                                eprintln!("unknown argument for xpc session: {other}");
                                print_usage();
                                std::process::exit(2);
                            }
                        }
                    }

                    if idx != args.len() {
                        eprintln!("xpc session does not take positional arguments (commands are read from stdin)");
                        print_usage();
                        std::process::exit(2);
                    }
                    if profile_arg.is_some() && service_arg.is_some() {
                        eprintln!("--profile cannot be combined with --service");
                        print_usage();
                        std::process::exit(2);
                    }

                    let target_profile = profile_arg
                        .as_ref()
                        .and_then(|id| profiles::find_profile(&profiles_manifest, id));

                    let service_id = if let Some(profile) = target_profile {
                        if profile.kind != "probe" {
                            eprintln!(
                                "profile is not a probe service: {} (kind={})",
                                profile.profile_id, profile.kind
                            );
                            std::process::exit(2);
                        }
                        profile.bundle_id.clone()
                    } else if let Some(service_id) = service_arg.as_ref() {
                        service_id.clone()
                    } else {
                        eprintln!("missing --profile or --service");
                        print_usage();
                        std::process::exit(2);
                    };

                    let profile = target_profile.or_else(|| {
                        let profile = resolve_profile_by_bundle_id(&profiles_manifest, &service_id);
                        if let Some(profile) = profile {
                            if profile.kind != "probe" {
                                eprintln!(
                                    "service is not a probe profile: {} (kind={})",
                                    profile.profile_id, profile.kind
                                );
                                std::process::exit(2);
                            }
                        }
                        profile
                    });

                    let (gate, reasons, label) = risk_gate_for_profile(profile);
                    let require_ack = matches!(gate, RiskGate::RequireAck);
                    let warn_only = matches!(gate, RiskGate::Warn);

                    if warn_only {
                        let profile_id = profile.map(|p| p.profile_id.clone());
                        let name = label
                            .clone()
                            .or_else(|| profile_id.clone())
                            .unwrap_or_else(|| service_id.clone());
                        if reasons.is_empty() {
                            eprintln!("warning: profile {name} is tier 1 (some concern)");
                        } else {
                            eprintln!(
                                "warning: profile {name} is tier 1 (reasons: {})",
                                reasons.join(", ")
                            );
                        }
                    }

                    if require_ack {
                        let profile_id = profile.map(|p| p.profile_id.clone());
                        let ack_ok = ack_risk
                            .as_ref()
                            .map(|ack| {
                                ack == &service_id
                                    || profile_id
                                        .as_ref()
                                        .map(|id| ack == id)
                                        .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        if !ack_ok {
                            let name = label
                                .or_else(|| profile_id.clone())
                                .unwrap_or_else(|| service_id.clone());
                            let ack_hint = profile_id.unwrap_or_else(|| service_id.clone());
                            let msg = if reasons.is_empty() {
                                format!("profile {name} is tier 2 (high concern); re-run with --ack-risk {ack_hint}")
                            } else {
                                format!(
                                    "profile {name} is tier 2 (reasons: {}); re-run with --ack-risk {ack_hint}",
                                    reasons.join(", ")
                                )
                            };
                            eprintln!("{msg}");
                            std::process::exit(2);
                        }
                    }

                    let mut forward_args: Vec<OsString> = Vec::new();
                    forward_args.push(OsString::from("session"));
                    if let Some(plan_id) = plan_id {
                        forward_args.push(OsString::from("--plan-id"));
                        forward_args.push(OsString::from(plan_id));
                    }
                    if let Some(correlation_id) = correlation_id {
                        forward_args.push(OsString::from("--correlation-id"));
                        forward_args.push(OsString::from(correlation_id));
                    }
                    if let Some(wait_spec) = wait_spec {
                        forward_args.push(OsString::from("--wait"));
                        forward_args.push(OsString::from(wait_spec));
                    }
                    if let Some(wait_timeout_ms) = wait_timeout_ms {
                        forward_args.push(OsString::from("--wait-timeout-ms"));
                        forward_args.push(OsString::from(wait_timeout_ms));
                    }
                    if let Some(wait_interval_ms) = wait_interval_ms {
                        forward_args.push(OsString::from("--wait-interval-ms"));
                        forward_args.push(OsString::from(wait_interval_ms));
                    }
                    if let Some(xpc_timeout_ms) = xpc_timeout_ms {
                        forward_args.push(OsString::from("--xpc-timeout-ms"));
                        forward_args.push(OsString::from(xpc_timeout_ms));
                    }
                    forward_args.push(OsString::from(service_id));

                    run_and_wait(cmd_path, forward_args);
                }
                _ => unreachable!(),
            }
        }
        Some("quarantine-lab") => {
            if args.len() < 3 {
                print_usage();
                std::process::exit(2);
            }
            let cmd_path = match resolve_contents_macos_tool("xpc-quarantine-client") {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}\n");
                    eprintln!("note: quarantine-lab mode requires the embedded `xpc-quarantine-client` tool under Contents/MacOS.");
                    std::process::exit(2);
                }
            };
            if let Err(err) = ensure_executable_file(&cmd_path) {
                eprintln!("{err}");
                std::process::exit(2);
            }
            run_and_wait(cmd_path, args[1..].to_vec());
        }
        _ => {
            // Legacy mode: `entitlement-jail <cmd> [args...]`
            let cmd_path = PathBuf::from(&args[0]);
            if cmd_path.is_absolute() && is_allowed_system_path(&cmd_path) {
                if let Err(err) = ensure_executable_file(&cmd_path) {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
                run_and_wait(cmd_path, args[1..].to_vec());
            }

            eprintln!(
                "unsupported invocation.\n\nThis tool no longer supports running arbitrary staged binaries by path (App Sandbox blocks process-exec* from writable locations).\nUse:\n  entitlement-jail run-system <platform-binary> [args...]\n  entitlement-jail run-embedded <tool-name> [args...]\n"
            );
            print_usage();
            std::process::exit(2);
        }
    }
}
