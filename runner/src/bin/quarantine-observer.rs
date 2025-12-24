#[path = "../json_contract.rs"]
#[allow(dead_code)]
mod json_contract;

use serde::Serialize;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn print_usage() {
    eprintln!(
        "\
usage:
  quarantine-observer <path> [--assess|--no-assess]

notes:
  - reads com.apple.quarantine xattr (if present)
  - optional: runs `spctl --assess --type execute` (does not execute the file)"
    );
}

fn cmd_output_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches('\n').to_string()
}

fn list_xattrs(path: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("/usr/bin/xattr")
        .arg(path)
        .output()
        .map_err(|e| format!("failed to run xattr: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "xattr failed (rc={}): {}",
            out.status.code().unwrap_or(1),
            cmd_output_to_string(&out.stderr)
        ));
    }
    Ok(cmd_output_to_string(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn read_xattr_value(path: &Path, name: &str) -> Result<String, String> {
    let out = Command::new("/usr/bin/xattr")
        .arg("-p")
        .arg(name)
        .arg(path)
        .output()
        .map_err(|e| format!("failed to run xattr -p: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "xattr -p failed (rc={}): {}",
            out.status.code().unwrap_or(1),
            cmd_output_to_string(&out.stderr)
        ));
    }
    Ok(cmd_output_to_string(&out.stdout))
}

#[derive(Default)]
struct SpctlResult {
    ran: bool,
    rc: Option<i32>,
    stdout: String,
    stderr: String,
    error: Option<String>,
}

#[derive(Serialize)]
struct ObserverLayerAttribution {
    seatbelt: String,
    quarantine: String,
    gatekeeper: String,
}

#[derive(Serialize)]
struct ObserverData {
    path: String,
    exists: bool,
    is_executable: Option<bool>,
    mode_octal: Option<String>,
    spctl_status_ran: bool,
    spctl_status_rc: Option<i32>,
    spctl_status_stdout: String,
    spctl_status_stderr: String,
    spctl_status_error: Option<String>,
    spctl_assessments_enabled: Option<bool>,
    quarantine_xattr_present: Option<bool>,
    quarantine_xattr_raw: Option<String>,
    quarantine_xattr_error: Option<String>,
    spctl_assess_ran: bool,
    spctl_rc: Option<i32>,
    spctl_stdout: String,
    spctl_stderr: String,
    spctl_error: Option<String>,
    layer_attribution: ObserverLayerAttribution,
}

fn run_spctl_status() -> SpctlResult {
    let mut res = SpctlResult::default();
    res.ran = true;

    let out = match Command::new("/usr/sbin/spctl").arg("--status").output() {
        Ok(out) => out,
        Err(e) => {
            res.error = Some(format!("failed to run spctl --status: {e}"));
            return res;
        }
    };

    res.rc = out.status.code();
    res.stdout = cmd_output_to_string(&out.stdout);
    res.stderr = cmd_output_to_string(&out.stderr);
    res
}

fn run_spctl_assess(path: &Path) -> SpctlResult {
    let mut res = SpctlResult::default();
    res.ran = true;

    let out = match Command::new("/usr/sbin/spctl")
        .arg("--assess")
        .arg("--type")
        .arg("execute")
        .arg("--verbose=4")
        .arg(path)
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            res.error = Some(format!("failed to run spctl: {e}"));
            return res;
        }
    };

    res.rc = out.status.code();
    res.stdout = cmd_output_to_string(&out.stdout);
    res.stderr = cmd_output_to_string(&out.stderr);
    res
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let spctl_status = run_spctl_status();
    let spctl_status_text = format!("{}\n{}", spctl_status.stdout, spctl_status.stderr);
    let spctl_assessments_enabled: Option<bool> = if spctl_status_text.contains("assessments enabled") {
        Some(true)
    } else if spctl_status_text.contains("assessments disabled") {
        Some(false)
    } else {
        None
    };

    let path = PathBuf::from(&args[0]);
    let mut assess = false;
    for arg in args.iter().skip(1) {
        match arg.to_str() {
            Some("--assess") => assess = true,
            Some("--no-assess") => assess = false,
            Some("-h") | Some("--help") => {
                print_usage();
                return;
            }
            _ => {
                eprintln!("unknown arg: {}", arg.to_string_lossy());
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(err) => {
            let data = ObserverData {
                path: path.display().to_string(),
                exists: false,
                is_executable: None,
                mode_octal: None,
                spctl_status_ran: spctl_status.ran,
                spctl_status_rc: spctl_status.rc,
                spctl_status_stdout: spctl_status.stdout.clone(),
                spctl_status_stderr: spctl_status.stderr.clone(),
                spctl_status_error: spctl_status.error.clone(),
                spctl_assessments_enabled,
                quarantine_xattr_present: None,
                quarantine_xattr_raw: None,
                quarantine_xattr_error: None,
                spctl_assess_ran: false,
                spctl_rc: None,
                spctl_stdout: String::new(),
                spctl_stderr: String::new(),
                spctl_error: None,
                layer_attribution: ObserverLayerAttribution {
                    seatbelt: "not_sandboxed".to_string(),
                    quarantine: "unknown".to_string(),
                    gatekeeper: "not_tested".to_string(),
                },
            };
            let result = json_contract::JsonResult {
                ok: false,
                rc: None,
                exit_code: Some(1),
                normalized_outcome: None,
                errno: None,
                error: Some(format!("metadata_failed: {err}")),
                stderr: None,
                stdout: None,
            };
            if let Err(err) = json_contract::print_envelope(
                "quarantine_observer_report",
                result,
                &data,
            ) {
                eprintln!("{err}");
            }
            std::process::exit(1);
        }
    };

    let perms = meta.permissions().mode() & 0o777;
    let is_executable = perms & 0o111 != 0;
    let mode_octal = format!("0o{perms:03o}");

    let mut quarantine_present = false;
    let mut quarantine_raw: Option<String> = None;
    let mut quarantine_err: Option<String> = None;

    match list_xattrs(&path) {
        Ok(names) => {
            if names.iter().any(|n| n == "com.apple.quarantine") {
                quarantine_present = true;
                match read_xattr_value(&path, "com.apple.quarantine") {
                    Ok(v) => quarantine_raw = Some(v),
                    Err(e) => quarantine_err = Some(e),
                }
            }
        }
        Err(e) => quarantine_err = Some(e),
    }

    let spctl = if assess {
        run_spctl_assess(&path)
    } else {
        SpctlResult::default()
    };

    let quarantine_attribution = if quarantine_err.is_some() {
        "xattr_error"
    } else if quarantine_present {
        "xattr_present"
    } else {
        "xattr_absent"
    };

    let gatekeeper_attribution = if spctl.ran {
        match (spctl.error.as_ref(), spctl.rc) {
            (Some(_), _) => "assess_error",
            (None, Some(0)) => "assess_ok",
            (None, Some(_)) => "assess_failed",
            (None, None) => "assess_unknown",
        }
    } else {
        "not_tested"
    };

    let data = ObserverData {
        path: path.display().to_string(),
        exists: true,
        is_executable: Some(is_executable),
        mode_octal: Some(mode_octal),
        spctl_status_ran: spctl_status.ran,
        spctl_status_rc: spctl_status.rc,
        spctl_status_stdout: spctl_status.stdout,
        spctl_status_stderr: spctl_status.stderr,
        spctl_status_error: spctl_status.error,
        spctl_assessments_enabled,
        quarantine_xattr_present: Some(quarantine_present),
        quarantine_xattr_raw: quarantine_raw,
        quarantine_xattr_error: quarantine_err,
        spctl_assess_ran: spctl.ran,
        spctl_rc: spctl.rc,
        spctl_stdout: spctl.stdout,
        spctl_stderr: spctl.stderr,
        spctl_error: spctl.error,
        layer_attribution: ObserverLayerAttribution {
            seatbelt: "not_sandboxed".to_string(),
            quarantine: quarantine_attribution.to_string(),
            gatekeeper: gatekeeper_attribution.to_string(),
        },
    };

    let result = json_contract::JsonResult::from_ok(true);
    if let Err(err) = json_contract::print_envelope("quarantine_observer_report", result, &data)
    {
        eprintln!("{err}");
    }
}
