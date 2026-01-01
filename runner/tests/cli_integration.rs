use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStderr, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn integration_enabled() -> bool {
    env::var("PW_INTEGRATION").ok().as_deref() == Some("1")
}

fn dlopen_tests_enabled() -> bool {
    env::var("PW_DLOPEN_TESTS").ok().as_deref() == Some("1")
}

const RUST_SCHEMA_VERSION: u64 = 1;
const PROBE_SCHEMA_VERSION: u64 = 1;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("runner crate should live under repo root")
        .to_path_buf()
}

fn pw_bin_path() -> PathBuf {
    if let Ok(val) = env::var("PW_BIN_PATH") {
        return PathBuf::from(val);
    }
    repo_root()
        .join("PolicyWitness.app")
        .join("Contents")
        .join("MacOS")
        .join("policy-witness")
}

fn require_pw_bin() -> PathBuf {
    let path = pw_bin_path();
    if !path.exists() {
        panic!(
            "PolicyWitness.app not found at {} (build the app or set PW_BIN_PATH)",
            path.display()
        );
    }
    path
}

fn run_pw(bin: &Path, args: &[&str]) -> Output {
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
    let path = env::var("PW_PREFLIGHT_JSON").ok()?;
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

struct SessionStream {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<String>,
    stderr: ChildStderr,
    lines: Vec<String>,
}

impl SessionStream {
    fn next_line(&mut self, timeout: Duration) -> Option<String> {
        match self.rx.recv_timeout(timeout) {
            Ok(line) => {
                self.lines.push(line.clone());
                Some(line)
            }
            Err(_) => None,
        }
    }

    fn drain(&mut self, timeout: Duration) {
        loop {
            match self.rx.recv_timeout(timeout) {
                Ok(line) => self.lines.push(line),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
}

fn spawn_xpc_session_stream(bin: &Path, args: &[&str]) -> SessionStream {
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

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    SessionStream {
        child,
        stdin,
        rx,
        stderr,
        lines: Vec::new(),
    }
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

fn finish_session_stream(mut session: SessionStream) -> SessionHoldResult {
    let status = session
        .child
        .wait()
        .unwrap_or_else(|err| panic!("failed to wait for session child: {err}"));

    session.drain(Duration::from_millis(50));
    let stdout = session.lines.join("\n");

    let mut stderr_buf = String::new();
    session
        .stderr
        .read_to_string(&mut stderr_buf)
        .unwrap_or_else(|err| panic!("failed to read session stderr: {err}"));

    SessionHoldResult {
        stdout,
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
    let bin = require_pw_bin();

    let verify_out = run_pw(&bin, &["verify-evidence"]);
    assert!(
        verify_out.status.success(),
        "verify-evidence failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_json = parse_json(&verify_out);
    assert_eq!(
        verify_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(RUST_SCHEMA_VERSION)
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

    let inspect_symbols = run_pw(&bin, &["inspect-macho", "evidence.symbols"]);
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

    let inspect_profiles = run_pw(&bin, &["inspect-macho", "evidence.profiles"]);
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

    let list_out = run_pw(&bin, &["list-profiles"]);
    assert!(
        list_out.status.success(),
        "list-profiles failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_json = parse_json(&list_out);
    assert_eq!(
        list_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(RUST_SCHEMA_VERSION)
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
    let minimal = profiles
        .iter()
        .find(|entry| {
            entry
                .get("profile_id")
                .and_then(|v| v.as_str())
                == Some("minimal")
        })
        .expect("minimal profile missing from list-profiles");
    let minimal_variants = minimal
        .get("variants")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("minimal profile missing variants"));
    assert!(
        minimal_variants.iter().any(|v| v.get("variant").and_then(|v| v.as_str()) == Some("base")),
        "minimal profile missing base variant"
    );
    assert!(
        minimal_variants.iter().any(|v| v.get("variant").and_then(|v| v.as_str()) == Some("injectable")),
        "minimal profile missing injectable variant"
    );

    let show_out = run_pw(&bin, &["show-profile", "minimal"]);
    assert!(
        show_out.status.success(),
        "show-profile minimal failed: {}",
        String::from_utf8_lossy(&show_out.stderr)
    );
    let show_json = parse_json(&show_out);
    assert_eq!(
        show_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(RUST_SCHEMA_VERSION)
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
    let variant = show_json
        .get("data")
        .and_then(|v| v.get("variant"))
        .and_then(|v| v.get("variant"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(variant, "base");

    let services_out = run_pw(&bin, &["list-services"]);
    assert!(
        services_out.status.success(),
        "list-services failed: {}",
        String::from_utf8_lossy(&services_out.stderr)
    );

    let probe_out = run_pw(&bin, &["xpc", "run", "--profile", "minimal", "probe_catalog"]);
    assert!(
        probe_out.status.success(),
        "xpc run minimal probe_catalog failed: {}",
        String::from_utf8_lossy(&probe_out.stderr)
    );
    let probe_json = parse_json(&probe_out);
    assert_eq!(
        probe_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(PROBE_SCHEMA_VERSION)
    );
    assert_eq!(
        probe_json.get("kind").and_then(|v| v.as_str()),
        Some("probe_response")
    );
    let catalog = parse_probe_catalog(&probe_out);
    assert_eq!(
        catalog.get("schema_version").and_then(|v| v.as_u64()),
        Some(PROBE_SCHEMA_VERSION)
    );

    let signpost_out =
        run_pw(&bin, &["xpc", "run", "--profile", "minimal", "--signposts", "probe_catalog"]);
    assert!(
        signpost_out.status.success(),
        "xpc run minimal --signposts probe_catalog failed: {}",
        String::from_utf8_lossy(&signpost_out.stderr)
    );

    let capture_out =
        run_pw(&bin, &["xpc", "run", "--profile", "minimal", "--capture-signposts", "probe_catalog"]);
    assert!(
        capture_out.status.success(),
        "xpc run minimal --capture-signposts probe_catalog failed: {}",
        String::from_utf8_lossy(&capture_out.stderr)
    );
    let capture_json = parse_json(&capture_out);
    assert!(
        capture_json
            .get("data")
            .and_then(|v| v.get("host_signpost_capture"))
            .is_some(),
        "probe_response missing data.host_signpost_capture"
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
                            .any(|s| s.as_str() == Some("pw_probe_fs_op"))
                    })
        }),
        "trace_symbols missing fs_op -> pw_probe_fs_op"
    );

    let fs_out = run_pw(
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

    let health_out = run_pw(&bin, &["health-check", "--profile", "minimal"]);
    assert!(
        health_out.status.success(),
        "health-check failed: {}",
        String::from_utf8_lossy(&health_out.stderr)
    );
    let health_json = parse_json(&health_out);
    assert_eq!(
        health_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(RUST_SCHEMA_VERSION)
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

    let injectable_out = run_pw(
        &bin,
        &[
            "xpc",
            "run",
            "--profile",
            "minimal",
            "--variant",
            "injectable",
            "probe_catalog",
        ],
    );
    assert!(
        injectable_out.status.success(),
        "injectable profile did not run: {}",
        String::from_utf8_lossy(&injectable_out.stderr)
    );

    let matrix_out = run_pw(
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
        Some(RUST_SCHEMA_VERSION)
    );
    assert_eq!(
        matrix_json.get("kind").and_then(|v| v.as_str()),
        Some("run_matrix_report")
    );
    assert_eq!(
        matrix_json
            .get("data")
            .and_then(|v| v.get("variant"))
            .and_then(|v| v.as_str()),
        Some("base")
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

    let bundle_out = run_pw(&bin, &["bundle-evidence"]);
    assert!(
        bundle_out.status.success(),
        "bundle-evidence failed: {}",
        String::from_utf8_lossy(&bundle_out.stderr)
    );
    let bundle_json = parse_json(&bundle_out);
    assert_eq!(
        bundle_json.get("schema_version").and_then(|v| v.as_u64()),
        Some(RUST_SCHEMA_VERSION)
    );
    assert_eq!(
        bundle_json.get("kind").and_then(|v| v.as_str()),
        Some("bundle_evidence_report")
    );

    if let Some(preflight) = preflight.as_ref() {
        let app_signed = preflight_bool(preflight, &["app", "signed"]) == Some(true);
        let injectable_get_task_allow = preflight_bool(
            preflight,
            &[
                "services",
                "minimal",
                "injectable",
                "entitlements",
                "get_task_allow",
            ],
        ) == Some(true);
        let inspector_signed = preflight_bool(preflight, &["inspector", "signed"]) == Some(true);
        let inspector_debugger = preflight_bool(preflight, &["inspector", "cs_debugger"]) == Some(true);
        let inspector_path = preflight_str(preflight, &["inspector", "path"]).unwrap_or_default();

        if app_signed && injectable_get_task_allow && inspector_signed && inspector_debugger {
            let inspector_bin = PathBuf::from(inspector_path);
            assert!(
                inspector_bin.exists(),
                "inspector binary missing at {}",
                inspector_bin.display()
            );

            // injectable variant should be attachable (task_for_pid allowed).
            let mut hold = spawn_xpc_session_hold(
                &bin,
                &[
                    "xpc",
                    "session",
                    "--profile",
                    "minimal",
                    "--variant",
                    "injectable",
                ],
            );
            let inspector_out = run_cmd(
                &inspector_bin,
                &[
                    "--bundle-id-prefix",
                    "com.yourteam.policy-witness.",
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
                "pw-inspector refused injectable pid: {}",
                String::from_utf8_lossy(&inspector_out.stderr)
            );

            hold.stdin
                .write_all(b"{\"command\":\"close_session\"}\n")
                .expect("write close_session");
            let hold_res = finish_session_hold(hold);
            assert!(
                hold_res.status_ok,
                "injectable xpc session failed:\n\nstdout:\n{}\n\nstderr:\n{}",
                hold_res.stdout,
                hold_res.stderr
            );

            // minimal should be refused by task_for_pid (but allowed as a target).
            let mut hold = spawn_xpc_session_hold(&bin, &["xpc", "session", "--profile", "minimal"]);
            let inspector_out = run_cmd(
                &inspector_bin,
                &[
                    "--bundle-id-prefix",
                    "com.yourteam.policy-witness.",
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
                "pw-inspector did not allow minimal identity"
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
                &[
                    "services",
                    "minimal",
                    "injectable",
                    "entitlements",
                    "disable_library_validation",
                ],
            ) == Some(true);
            if dylib_ready && relax_ok {
                let dylib = PathBuf::from(dylib_path);
                assert!(dylib.exists(), "test dylib missing at {}", dylib.display());
                let dlopen_out = run_pw(
                    &bin,
                    &[
                        "xpc",
                        "run",
                        "--profile",
                        "minimal",
                        "--variant",
                        "injectable",
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
            eprintln!("skip dlopen test: set PW_DLOPEN_TESTS=1 to enable");
        }

        let jit_ok = preflight_bool(
            preflight,
            &["services", "minimal", "injectable", "entitlements", "allow_jit"],
        ) == Some(true)
            && preflight_bool(
                preflight,
                &[
                    "services",
                    "minimal",
                    "injectable",
                    "entitlements",
                    "allow_unsigned_executable_memory",
                ],
            ) == Some(true);
        if jit_ok {
            let jit_map_out = run_pw(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "minimal",
                    "--variant",
                    "injectable",
                    "jit_map_jit",
                ],
            );
            assert!(
                jit_map_out.status.success(),
                "jit_map_jit failed: {}",
                String::from_utf8_lossy(&jit_map_out.stderr)
            );

            let jit_rwx_out = run_pw(
                &bin,
                &[
                    "xpc",
                    "run",
                    "--profile",
                    "minimal",
                    "--variant",
                    "injectable",
                    "jit_rwx_legacy",
                ],
            );
            let jit_rwx_json = parse_json(&jit_rwx_out);
            let outcome = jit_rwx_json
                .get("result")
                .and_then(|v| v.get("normalized_outcome"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(
                matches!(outcome, "ok" | "permission_error"),
                "jit_rwx_legacy unexpected outcome: {outcome}"
            );
        } else {
            eprintln!("skip jit tests: missing jit entitlements");
        }

        let net_client_ok = preflight_bool(
            preflight,
            &["services", "net_client", "base", "entitlements", "network_client"],
        ) == Some(true);
        if net_client_ok {
            let net_min_out = run_pw(
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

            let net_client_out = run_pw(
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
        eprintln!("skip inspector/dlopen/jit/network tests: missing PW_PREFLIGHT_JSON");
    }
}

#[test]
fn xpc_session_wait_flow() {
    if !integration_enabled() {
        return;
    }

    let bin = require_pw_bin();
    let mut session = spawn_xpc_session_stream(
        &bin,
        &[
            "xpc",
            "session",
            "--profile",
            "minimal",
            "--wait",
            "fifo:auto",
            "--wait-timeout-ms",
            "10000",
        ],
    );

    let mut pid: Option<i64> = None;
    let mut wait_path: Option<String> = None;
    let mut have_wait_ready = false;

    let mut line_idx = 0usize;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        let line = match session.next_line(Duration::from_secs(1)) {
            Some(line) => line,
            None => continue,
        };
        line_idx += 1;
        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(val) => val,
            Err(_) => continue,
        };
        match parsed.get("kind").and_then(|v| v.as_str()) {
            Some("xpc_session_error") => {
                panic!("unexpected session error: {line}");
            }
            Some("xpc_session_event") => {
                let data = parsed.get("data").cloned().unwrap_or(serde_json::Value::Null);
                let event = data.get("event").and_then(|v| v.as_str()).unwrap_or("");
                if event == "session_ready" {
                    pid = data.get("pid").and_then(|v| v.as_i64());
                    if let Some(path) = data.get("wait_path").and_then(|v| v.as_str()) {
                        wait_path = Some(path.to_string());
                    }
                } else if event == "wait_ready" {
                    have_wait_ready = true;
                    if wait_path.is_none() {
                        if let Some(path) = data.get("wait_path").and_then(|v| v.as_str()) {
                            wait_path = Some(path.to_string());
                        }
                    }
                }
            }
            _ => {}
        }

        if pid.is_some() && wait_path.is_some() && have_wait_ready {
            break;
        }
    }

    let pid = pid.unwrap_or(0);
    if pid <= 0 {
        panic!(
            "missing/invalid pid in session_ready; stdout so far:\n{}",
            session.lines.join("\n")
        );
    }
    let wait_path = wait_path.unwrap_or_else(|| {
        panic!(
            "missing wait_path in session events; stdout so far:\n{}",
            session.lines.join("\n")
        )
    });

    let fifo_deadline = Instant::now() + Duration::from_secs(5);
    let mut is_fifo = false;
    while Instant::now() < fifo_deadline {
        if let Ok(meta) = std::fs::metadata(&wait_path) {
            if meta.file_type().is_fifo() {
                is_fifo = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        is_fifo,
        "expected wait_path FIFO at {wait_path}; stdout so far:\n{}",
        session.lines.join("\n")
    );

    let mut fifo = std::fs::OpenOptions::new()
        .write(true)
        .open(&wait_path)
        .unwrap_or_else(|err| panic!("failed to open wait FIFO {wait_path}: {err}"));
    fifo.write_all(b"go")
        .unwrap_or_else(|err| panic!("failed to write wait FIFO {wait_path}: {err}"));

    let mut trigger_idx: Option<usize> = None;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        let line = match session.next_line(Duration::from_secs(1)) {
            Some(line) => line,
            None => continue,
        };
        line_idx += 1;
        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(val) => val,
            Err(_) => continue,
        };
        if parsed.get("kind").and_then(|v| v.as_str()) == Some("xpc_session_error") {
            panic!("unexpected session error: {line}");
        }
        if parsed.get("kind").and_then(|v| v.as_str()) != Some("xpc_session_event") {
            continue;
        }
        let event = parsed
            .get("data")
            .and_then(|v| v.get("event"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if event == "trigger_received" {
            trigger_idx = Some(line_idx);
            break;
        }
    }

    let trigger_idx = trigger_idx.unwrap_or_else(|| {
        panic!(
            "timed out waiting for trigger_received; stdout so far:\n{}",
            session.lines.join("\n")
        )
    });

    session
        .stdin
        .write_all(b"{\"command\":\"run_probe\",\"probe_id\":\"capabilities_snapshot\"}\n")
        .expect("write run_probe");

    let mut probe_start_idx: Option<usize> = None;
    let mut probe_done = false;
    let mut probe_ok = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let line = match session.next_line(Duration::from_secs(1)) {
            Some(line) => line,
            None => continue,
        };
        line_idx += 1;
        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(val) => val,
            Err(_) => continue,
        };
        match parsed.get("kind").and_then(|v| v.as_str()) {
            Some("xpc_session_error") => {
                panic!("unexpected session error: {line}");
            }
            Some("xpc_session_event") => {
                let event = parsed
                    .get("data")
                    .and_then(|v| v.get("event"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if event == "probe_starting" {
                    probe_start_idx = Some(line_idx);
                } else if event == "probe_done" {
                    probe_done = true;
                }
            }
            Some("probe_response") => {
                let probe_id = parsed
                    .get("data")
                    .and_then(|v| v.get("probe_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if probe_id == "capabilities_snapshot" {
                    let outcome = parsed
                        .get("result")
                        .and_then(|v| v.get("normalized_outcome"))
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            parsed
                                .get("data")
                                .and_then(|v| v.get("normalized_outcome"))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or("");
                    assert_eq!(
                        outcome, "ok",
                        "unexpected normalized_outcome for capabilities_snapshot"
                    );
                    probe_ok = true;
                }
            }
            _ => {}
        }
        if probe_done && probe_ok {
            break;
        }
    }

    let probe_start_idx = probe_start_idx.unwrap_or_else(|| {
        panic!(
            "missing probe_starting event; stdout so far:\n{}",
            session.lines.join("\n")
        )
    });
    assert!(
        trigger_idx < probe_start_idx,
        "expected trigger_received to precede probe_starting"
    );
    assert!(
        probe_done && probe_ok,
        "expected probe_done and probe_response; stdout so far:\n{}",
        session.lines.join("\n")
    );

    session
        .stdin
        .write_all(b"{\"command\":\"close_session\"}\n")
        .expect("write close_session");

    let mut saw_closed = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let line = match session.next_line(Duration::from_secs(1)) {
            Some(line) => line,
            None => continue,
        };
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) {
            if parsed.get("kind").and_then(|v| v.as_str()) == Some("xpc_session_event") {
                let event = parsed
                    .get("data")
                    .and_then(|v| v.get("event"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if event == "session_closed" {
                    saw_closed = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_closed,
        "expected session_closed event; stdout so far:\n{}",
        session.lines.join("\n")
    );

    let result = finish_session_stream(session);
    assert!(
        result.status_ok,
        "xpc session exited with failure:\n\nstdout:\n{}\n\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}
