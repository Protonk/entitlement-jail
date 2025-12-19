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

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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
            let json = format!(
                "{{\"path\":\"{}\",\"exists\":false,\"error\":\"{}\",\"layer_attribution\":{{\"seatbelt\":\"not_sandboxed\",\"quarantine\":\"unknown\",\"gatekeeper\":\"not_tested\"}}}}",
                json_escape(&path.display().to_string()),
                json_escape(&format!("{err}"))
            );
            println!("{json}");
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

    let json = format!(
        "{{\
\"path\":\"{}\",\
\"exists\":true,\
\"is_executable\":{},\
\"mode_octal\":\"{}\",\
\"spctl_status_ran\":{},\
\"spctl_status_rc\":{},\
\"spctl_status_stdout\":\"{}\",\
\"spctl_status_stderr\":\"{}\",\
\"spctl_status_error\":{},\
\"spctl_assessments_enabled\":{},\
\"quarantine_xattr_present\":{},\
\"quarantine_xattr_raw\":{},\
\"quarantine_xattr_error\":{},\
\"spctl_assess_ran\":{},\
\"spctl_rc\":{},\
\"spctl_stdout\":\"{}\",\
\"spctl_stderr\":\"{}\",\
\"spctl_error\":{},\
\"layer_attribution\":{{\"seatbelt\":\"not_sandboxed\",\"quarantine\":\"{}\",\"gatekeeper\":\"{}\"}}\
}}",
        json_escape(&path.display().to_string()),
        if is_executable { "true" } else { "false" },
        json_escape(&mode_octal),
        if spctl_status.ran { "true" } else { "false" },
        match spctl_status.rc {
            Some(rc) => rc.to_string(),
            None => "null".to_string(),
        },
        json_escape(&spctl_status.stdout),
        json_escape(&spctl_status.stderr),
        match spctl_status.error.as_ref() {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        },
        match spctl_assessments_enabled {
            Some(true) => "true".to_string(),
            Some(false) => "false".to_string(),
            None => "null".to_string(),
        },
        if quarantine_present { "true" } else { "false" },
        match quarantine_raw.as_ref() {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        },
        match quarantine_err.as_ref() {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        },
        if spctl.ran { "true" } else { "false" },
        match spctl.rc {
            Some(rc) => rc.to_string(),
            None => "null".to_string(),
        },
        json_escape(&spctl.stdout),
        json_escape(&spctl.stderr),
        match spctl.error.as_ref() {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        },
        quarantine_attribution,
        gatekeeper_attribution
    );

    println!("{json}");
}
