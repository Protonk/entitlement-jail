use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStderr, ChildStdout, Command, Output, Stdio};

fn integration_enabled() -> bool {
    env::var("EJ_INTEGRATION").ok().as_deref() == Some("1")
}

fn dlopen_tests_enabled() -> bool {
    env::var("EJ_DLOPEN_TESTS").ok().as_deref() == Some("1")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("runner crate should live under repo root")
        .to_path_buf()
}

fn ej_bin_path() -> PathBuf {
    if let Ok(val) = env::var("EJ_BIN_PATH") {
        return PathBuf::from(val);
    }
    repo_root()
        .join("EntitlementJail.app")
        .join("Contents")
        .join("MacOS")
        .join("entitlement-jail")
}

fn require_ej_bin() -> PathBuf {
    let path = ej_bin_path();
    if !path.exists() {
        panic!(
            "EntitlementJail.app not found at {} (build the app or set EJ_BIN_PATH)",
            path.display()
        );
    }
    path
}

fn run_ej(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", bin.display()))
}

fn run_cmd(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", bin.display()))
}

fn parse_json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("failed to parse JSON output: {err}\nstdout:\n{stdout}"))
}

fn load_preflight() -> Option<serde_json::Value> {
    let path = env::var("EJ_PREFLIGHT_JSON").ok()?;
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn lookup_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    Some(cur)
}

fn preflight_bool(preflight: &serde_json::Value, path: &[&str]) -> Option<bool> {
    lookup_path(preflight, path).and_then(|v| v.as_bool())
}

fn preflight_str(preflight: &serde_json::Value, path: &[&str]) -> Option<String> {
    lookup_path(preflight, path)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn parse_probe_catalog(output: &Output) -> serde_json::Value {
    let resp = parse_json(output);
    let stdout = resp
        .get("result")
        .and_then(|v| v.get("stdout"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    serde_json::from_str(stdout).unwrap_or_else(|err| {
        panic!("failed to parse probe_catalog stdout: {err}\nstdout:\n{stdout}")
    })
}

struct SessionHold {
    child: Child,
    stdin: ChildStdin,
    stdout_reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
    stdout_buf: String,
    pid: i32,
}

struct SessionHoldResult {
    stdout: String,
    stderr: String,
    status_ok: bool,
}

fn spawn_xpc_session_hold(bin: &Path, args: &[&str]) -> SessionHold {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn {}: {err}", bin.display()));

    let stdin = child.stdin.take().expect("missing stdin");
    let stdout = child.stdout.take().expect("missing stdout");
    let stderr = child.stderr.take().expect("missing stderr");

    let mut reader = BufReader::new(stdout);
    let mut stdout_buf = String::new();

    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .unwrap_or_else(|err| panic!("failed to read session stdout: {err}"));
        if n == 0 {
            break;
        }
        stdout_buf.push_str(&line);

        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed.get("kind").and_then(|v| v.as_str()) != Some("xpc_session_event") {
            continue;
        }
        let data = parsed.get("data").cloned().unwrap_or(serde_json::Value::Null);
        if data.get("event").and_then(|v| v.as_str()) != Some("session_ready") {
            continue;
        }

        let pid = data
            .get("pid")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(0);
        let token = data
            .get("session_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if pid <= 0 || token.is_empty() {
            panic!("malformed session_ready event:\n{line}\n\nstdout so far:\n{stdout_buf}");
        }

        return SessionHold {
            child,
            stdin,
            stdout_reader: reader,
            stderr,
            stdout_buf,
            pid,
        };
    }

    panic!("failed to observe session_ready event\nstdout:\n{stdout_buf}");
}

fn finish_session_hold(mut hold: SessionHold) -> SessionHoldResult {
    let status = hold
        .child
        .wait()
        .unwrap_or_else(|err| panic!("failed to wait for session child: {err}"));

    let mut rest = String::new();
    hold.stdout_reader
        .read_to_string(&mut rest)
        .unwrap_or_else(|err| panic!("failed to read remaining session stdout: {err}"));
    hold.stdout_buf.push_str(&rest);

    let mut stderr_buf = String::new();
    hold.stderr
        .read_to_string(&mut stderr_buf)
        .unwrap_or_else(|err| panic!("failed to read session stderr: {err}"));

    SessionHoldResult {
        stdout: hold.stdout_buf,
        stderr: stderr_buf,
        status_ok: status.success(),
    }
}

#[test]
fn cli_integration_smoke() {
    if !integration_enabled() {
        return;
    }

    let preflight = load_preflight();
    let bin = require_ej_bin();

    let verify_out = run_ej(&bin, &["verify-evidence"]);
    assert!(
        verify_out.status.success(),
        "verify-evidence failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_json = parse_json(&verify_out);
    assert_eq!(
        verify_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        verify_json.get("kind").and_then(|v| v.as_str()),
        Some("verify_evidence_report")
    );
    assert_eq!(
        verify_json
            .get("result")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    let inspect_symbols = run_ej(&bin, &["inspect-macho", "evidence.symbols"]);
    assert!(
        inspect_symbols.status.success(),
        "inspect-macho evidence.symbols failed: {}",
        String::from_utf8_lossy(&inspect_symbols.stderr)
    );
    let inspect_symbols_json = parse_json(&inspect_symbols);
    let inspect_id = inspect_symbols_json
        .get("data")
        .and_then(|v| v.get("entry"))
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(inspect_id, "evidence.symbols");

    let inspect_profiles = run_ej(&bin, &["inspect-macho", "evidence.profiles"]);
    assert!(
        inspect_profiles.status.success(),
        "inspect-macho evidence.profiles failed: {}",
        String::from_utf8_lossy(&inspect_profiles.stderr)
    );
    let inspect_profiles_json = parse_json(&inspect_profiles);
    let inspect_profiles_id = inspect_profiles_json
        .get("data")
        .and_then(|v| v.get("entry"))
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(inspect_profiles_id, "evidence.profiles");

    let list_out = run_ej(&bin, &["list-profiles"]);
    assert!(
        list_out.status.success(),
        "list-profiles failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_json = parse_json(&list_out);
    assert_eq!(
        list_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        list_json.get("kind").and_then(|v| v.as_str()),
        Some("profiles_report")
    );
    let profiles = list_json
        .get("data")
        .and_then(|v| v.get("profiles"))
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("list-profiles missing profiles array"));
    assert!(!profiles.is_empty(), "list-profiles returned empty list");

    let show_out = run_ej(&bin, &["show-profile", "minimal"]);
    assert!(
        show_out.status.success(),
        "show-profile minimal failed: {}",
        String::from_utf8_lossy(&show_out.stderr)
    );
    let show_json = parse_json(&show_out);
    assert_eq!(
        show_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        show_json.get("kind").and_then(|v| v.as_str()),
        Some("profile_report")
    );
    let profile_id = show_json
        .get("data")
        .and_then(|v| v.get("profile"))
        .and_then(|v| v.get("profile_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(profile_id, "minimal");

    let services_out = run_ej(&bin, &["list-services"]);
    assert!(
        services_out.status.success(),
        "list-services failed: {}",
        String::from_utf8_lossy(&services_out.stderr)
    );

    let probe_out = run_ej(&bin, &["xpc", "run", "--profile", "minimal", "probe_catalog"]);
    assert!(
        probe_out.status.success(),
        "xpc run minimal probe_catalog failed: {}",
        String::from_utf8_lossy(&probe_out.stderr)
    );
    let probe_json = parse_json(&probe_out);
    assert_eq!(
        probe_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        probe_json.get("kind").and_then(|v| v.as_str()),
        Some("probe_response")
    );
    let catalog = parse_probe_catalog(&probe_out);
    assert_eq!(
        catalog.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );

    let trace = catalog
        .get("trace_symbols")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("probe_catalog missing trace_symbols"));
    assert!(
        trace.iter().any(|entry| {
            entry.get("probe_id").and_then(|v| v.as_str()) == Some("fs_op")
                && entry
                    .get("symbols")
                    .and_then(|v| v.as_array())
                    .is_some_and(|symbols| {
                        symbols
                            .iter()
                            .any(|s| s.as_str() == Some("ej_probe_fs_op"))
                    })
        }),
        "trace_symbols missing fs_op -> ej_probe_fs_op"
    );

    let fs_out = run_ej(
        &bin,
        &[
            "xpc",
            "run",
            "--profile",
            "minimal",
            "fs_op",
            "--op",
            "stat",
            "--path-class",
            "tmp",
        ],
    );
    assert!(
        fs_out.status.success(),
        "xpc run minimal fs_op failed: {}",
        String::from_utf8_lossy(&fs_out.stderr)
    );

    let health_out = run_ej(&bin, &["health-check", "--profile", "minimal"]);
    assert!(
        health_out.status.success(),
        "health-check failed: {}",
        String::from_utf8_lossy(&health_out.stderr)
    );
    let health_json = parse_json(&health_out);
    assert_eq!(
        health_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        health_json.get("kind").and_then(|v| v.as_str()),
        Some("health_check_report")
    );
    assert_eq!(
        health_json
            .get("result")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    let gate_out = run_ej(
        &bin,
        &["xpc", "run", "--profile", "fully_injectable", "probe_catalog"],
    );
    assert!(
        !gate_out.status.success(),
        "expected tier2 profile to require --ack-risk"
    );

    let allow_out = run_ej(
        &bin,
        &[
            "xpc",
            "run",
            "--profile",
            "fully_injectable",
            "--ack-risk",
            "fully_injectable",
            "probe_catalog",
        ],
    );
    assert!(
        allow_out.status.success(),
        "tier2 profile did not run with --ack-risk: {}",
        String::from_utf8_lossy(&allow_out.stderr)
    );

    let matrix_out = run_ej(
        &bin,
        &["run-matrix", "--group", "baseline", "capabilities_snapshot"],
    );
    assert!(
        matrix_out.status.success(),
        "run-matrix failed: {}",
        String::from_utf8_lossy(&matrix_out.stderr)
    );
    let matrix_json = parse_json(&matrix_out);
    assert_eq!(
        matrix_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        matrix_json.get("kind").and_then(|v| v.as_str()),
        Some("run_matrix_report")
    );
    let matrix_output = matrix_json
        .get("data")
        .and_then(|v| v.get("output_dir"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(!matrix_output.is_empty(), "run-matrix output_dir missing");
    let matrix_dir = PathBuf::from(matrix_output);
    assert!(matrix_dir.join("run-matrix.json").exists());
    assert!(matrix_dir.join("run-matrix.table.txt").exists());

    let bundle_out = run_ej(&bin, &["bundle-evidence"]);
    assert!(
        bundle_out.status.success(),
        "bundle-evidence failed: {}",
        String::from_utf8_lossy(&bundle_out.stderr)
    );
    let bundle_json = parse_json(&bundle_out);
    assert_eq!(
        bundle_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        bundle_json.get("kind").and_then(|v| v.as_str()),
        Some("bundle_evidence_report")
    );

    if let Some(preflight) = preflight.as_ref() {
        let app_signed = preflight_bool(preflight, &["app", "signed"]) == Some(true);
        let get_task_allow_entitled = preflight_bool(
            preflight,
            &["services", "get-task-allow", "entitlements", "get_task_allow"],
        ) == Some(true);
        let inspector_signed = preflight_bool(preflight, &["inspector", "signed"]) == Some(true);
        let inspector_debugger = preflight_bool(preflight, &["inspector", "cs_debugger"]) == Some(true);
        let inspector_path = preflight_str(preflight, &["inspector", "path"]).unwrap_or_default();

        if app_signed && get_task_allow_entitled && inspector_signed && inspector_debugger {
            let inspector_bin = PathBuf::from(inspector_path);
            assert!(
                inspector_bin.exists(),
                "inspector binary missing at {}",
                inspector_bin.display()
            );

            // get-task-allow should be attachable (task_for_pid allowed).
            let mut hold = spawn_xpc_session_hold(
                &bin,
                &[
                    "xpc",
                    "session",
                    "--profile",
                    "get-task-allow",
                    "--ack-risk",
                    "get-task-allow",
                ],
            );
            let inspector_out = run_cmd(
                &inspector_bin,
                &[
                    "--bundle-id-prefix",
                    "com.yourteam.entitlement-jail.",
                    &hold.pid.to_string(),
                ],
            );
            let inspector_json = parse_json(&inspector_out);
            assert_eq!(
                inspector_json
                    .get("result")
                    .and_then(|v| v.get("ok"))
                    .and_then(|v| v.as_bool()),
                Some(true),
                "ej-inspector refused get-task-allow pid: {}",
                String::from_utf8_lossy(&inspector_out.stderr)
            );

            hold.stdin
                .write_all(b"{\"command\":\"close_session\"}\n")
                .expect("write close_session");
            let hold_res = finish_session_hold(hold);
            assert!(
                hold_res.status_ok,
                "get-task-allow xpc session failed:\n\nstdout:\n{}\n\nstderr:\n{}",
                hold_res.stdout,
                hold_res.stderr
            );

            // minimal should be refused by task_for_pid (but still allowed as a target).
            let mut hold = spawn_xpc_session_hold(&bin, &["xpc", "session", "--profile", "minimal"]);
            let inspector_out = run_cmd(
                &inspector_bin,
                &[
                    "--bundle-id-prefix",
                    "com.yourteam.entitlement-jail.",
                    &hold.pid.to_string(),
                ],
            );
            let inspector_json = parse_json(&inspector_out);
            assert_eq!(
                inspector_json
                    .get("data")
                    .and_then(|v| v.get("allowed"))
                    .and_then(|v| v.as_bool()),
                Some(true),
                "ej-inspector did not allow minimal identity"
            );
            assert_eq!(
                inspector_json
                    .get("data")
                    .and_then(|v| v.get("attach_result"))
                    .and_then(|v| v.as_str()),
                Some("refused"),
                "expected task_for_pid to be refused for minimal"
            );

            hold.stdin
                .write_all(b"{\"command\":\"close_session\"}\n")
                .expect("write close_session");
            let hold_res = finish_session_hold(hold);
            assert!(
                hold_res.status_ok,
                "minimal xpc session failed:\n\nstdout:\n{}\n\nstderr:\n{}",
                hold_res.stdout,
                hold_res.stderr
            );
        } else {
            eprintln!("skip inspector attach tests: preflight indicates signatures/entitlements are not ready");
        }

        if dlopen_tests_enabled() {
            let dylib_ready = preflight_bool(preflight, &["test_dylib", "signed"]) == Some(true);
            let dylib_path = preflight_str(preflight, &["test_dylib", "path"]).unwrap_or_default();
            let relax_ok = preflight_bool(
                preflight,
                &["services", "fully_injectable", "entitlements", "disable_library_validation"],
            ) == Some(true);
            if dylib_ready && relax_ok {
                let dylib = PathBuf::from(dylib_path);
                assert!(dylib.exists(), "test dylib missing at {}", dylib.display());
                let dlopen_out = run_ej(
                    &bin,
                    &[
                        "xpc",
                        "run",
                        "--profile",
                        "fully_injectable",
                        "--ack-risk",
                        "fully_injectable",
                        "dlopen_external",
                        "--path",
                        dylib.to_str().unwrap_or(""),
                    ],
                );
                assert!(
                    dlopen_out.status.success(),
                    "dlopen_external failed: {}",
                    String::from_utf8_lossy(&dlopen_out.stderr)
                );
                let dlopen_json = parse_json(&dlopen_out);
                assert_eq!(
                    dlopen_json
                        .get("result")
                        .and_then(|v| v.get("ok"))
                        .and_then(|v| v.as_bool()),
                    Some(true),
                    "dlopen_external did not succeed"
                );
            } else {
                eprintln!("skip dlopen test: missing signed test dylib or entitlement");
            }
        } else {
            eprintln!("skip dlopen test: set EJ_DLOPEN_TESTS=1 to enable");
        }

        let jit_ok = preflight_bool(
            preflight,
            &["services", "fully_injectable", "entitlements", "allow_jit"],
        ) == Some(true)
            && preflight_bool(
                preflight,
                &[
                    "services",
                    "fully_injectable",
                    "entitlements",
                    "allow_unsigned_executable_memory",
                ],
            ) == Some(true);
        if jit_ok {
            let jit_map_out = run_ej(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "fully_injectable",
                    "--ack-risk",
                    "fully_injectable",
                    "jit_map_jit",
                ],
            );
            assert!(
                jit_map_out.status.success(),
                "jit_map_jit failed: {}",
                String::from_utf8_lossy(&jit_map_out.stderr)
            );

            let jit_rwx_out = run_ej(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "fully_injectable",
                    "--ack-risk",
                    "fully_injectable",
                    "jit_rwx_legacy",
                ],
            );
            assert!(
                jit_rwx_out.status.success(),
                "jit_rwx_legacy failed: {}",
                String::from_utf8_lossy(&jit_rwx_out.stderr)
            );
        } else {
            eprintln!("skip jit tests: missing jit entitlements");
        }

        let net_client_ok = preflight_bool(
            preflight,
            &["services", "net_client", "entitlements", "network_client"],
        ) == Some(true);
        if net_client_ok {
            let net_min_out = run_ej(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "minimal",
                    "net_op",
                    "--op",
                    "tcp_connect",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "9",
                ],
            );
            let net_min_json = parse_json(&net_min_out);
            assert_eq!(
                net_min_json
                    .get("result")
                    .and_then(|v| v.get("normalized_outcome"))
                    .and_then(|v| v.as_str()),
                Some("permission_error"),
                "expected permission_error for minimal net_op"
            );

            let net_client_out = run_ej(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "net_client",
                    "net_op",
                    "--op",
                    "tcp_connect",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "9",
                ],
            );
            let net_client_json = parse_json(&net_client_out);
            let outcome = net_client_json
                .get("result")
                .and_then(|v| v.get("normalized_outcome"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert_ne!(
                outcome,
                "permission_error",
                "network client should not be permission_error"
            );
        } else {
            eprintln!("skip network test: missing network client entitlement");
        }
    } else {
        eprintln!("skip inspector/dlopen/jit/network tests: missing EJ_PREFLIGHT_JSON");
    }
}
