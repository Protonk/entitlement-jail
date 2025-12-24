#[path = "../json_contract.rs"]
#[allow(dead_code)]
mod json_contract;

use serde::Serialize;
use std::ffi::{CStr, OsString};
use std::os::raw::{c_char, c_int, c_void};
use std::process::Command;

const PATH_MAX: usize = 4096;

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

#[link(name = "System")]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn task_for_pid(task: u32, pid: c_int, target: *mut u32) -> c_int;
    fn mach_error_string(err: c_int) -> *const c_char;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
}

fn print_usage() {
    eprintln!(
        "\
usage:
  ej-inspector <pid> [--team-id <TEAMID>] [--bundle-id <id>|--bundle-id-prefix <prefix>] [--no-attach]

notes:
  - validates target identity via codesign output (TeamIdentifier + Identifier)
  - if allowed, attempts task_for_pid and immediately deallocates the task port\n"
    );
}

fn pid_path(pid: i32) -> Result<String, String> {
    let mut buf = vec![0u8; PATH_MAX];
    let rc = unsafe { proc_pidpath(pid as c_int, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if rc <= 0 {
        return Err("proc_pidpath failed".to_string());
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    Ok(cstr.to_string_lossy().to_string())
}

#[derive(Default)]
struct CodeSignInfo {
    identifier: Option<String>,
    team_id: Option<String>,
    rc: Option<i32>,
    stderr: String,
    error: Option<String>,
}

#[derive(Serialize)]
struct InspectorData {
    pid: i32,
    path: Option<String>,
    identifier: Option<String>,
    team_id: Option<String>,
    expected_team_id: String,
    expected_bundle_id: Option<String>,
    expected_bundle_id_prefix: Option<String>,
    id_ok: bool,
    team_ok: bool,
    allowed: bool,
    codesign_rc: Option<i32>,
    codesign_error: Option<String>,
    attach_attempted: bool,
    attach_result: String,
    attach_rc: Option<i32>,
    attach_error: Option<String>,
}

fn codesign_info(path: &str) -> CodeSignInfo {
    let mut out = CodeSignInfo::default();
    let output = match Command::new("/usr/bin/codesign").arg("-dvv").arg(path).output() {
        Ok(output) => output,
        Err(err) => {
            out.error = Some(format!("failed to run codesign: {err}"));
            return out;
        }
    };

    out.rc = output.status.code();
    out.stderr = String::from_utf8_lossy(&output.stderr).to_string();

    for line in out.stderr.lines() {
        if let Some(rest) = line.strip_prefix("Identifier=") {
            out.identifier = Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            let val = rest.trim().to_string();
            if !val.is_empty() {
                out.team_id = Some(val);
            }
        }
    }

    out
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let mut pid: Option<i32> = None;
    let mut team_id: Option<String> = None;
    let mut bundle_id: Option<String> = None;
    let mut bundle_prefix: Option<String> = None;
    let mut no_attach = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].to_string_lossy();
        match arg.as_ref() {
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "--team-id" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --team-id");
                    print_usage();
                    std::process::exit(2);
                }
                team_id = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--bundle-id" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --bundle-id");
                    print_usage();
                    std::process::exit(2);
                }
                bundle_id = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--bundle-id-prefix" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --bundle-id-prefix");
                    print_usage();
                    std::process::exit(2);
                }
                bundle_prefix = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--no-attach" => {
                no_attach = true;
                i += 1;
            }
            _ => {
                if pid.is_none() {
                    pid = arg.parse::<i32>().ok();
                } else {
                    eprintln!("unknown arg: {arg}");
                    print_usage();
                    std::process::exit(2);
                }
                i += 1;
            }
        }
    }

    let pid = match pid {
        Some(pid) if pid > 0 => pid,
        _ => {
            eprintln!("missing/invalid pid");
            print_usage();
            std::process::exit(2);
        }
    };

    if bundle_id.is_some() && bundle_prefix.is_some() {
        eprintln!("use either --bundle-id or --bundle-id-prefix (not both)");
        std::process::exit(2);
    }

    if bundle_id.is_none() && bundle_prefix.is_none() {
        bundle_prefix = Some("com.yourteam.entitlement-jail.".to_string());
    }

    if team_id.is_none() {
        if let Ok(self_path) = std::env::current_exe() {
            let info = codesign_info(&self_path.display().to_string());
            if let Some(tid) = info.team_id {
                team_id = Some(tid);
            }
        }
    }

    let team_id = match team_id {
        Some(tid) => tid,
        None => {
            eprintln!("missing --team-id (and could not infer from self signature)");
            std::process::exit(2);
        }
    };

    let path = match pid_path(pid) {
        Ok(path) => path,
        Err(err) => {
            let data = InspectorData {
                pid,
                path: None,
                identifier: None,
                team_id: None,
                expected_team_id: team_id.clone(),
                expected_bundle_id: bundle_id.clone(),
                expected_bundle_id_prefix: bundle_prefix.clone(),
                id_ok: false,
                team_ok: false,
                allowed: false,
                codesign_rc: None,
                codesign_error: None,
                attach_attempted: false,
                attach_result: "skipped".to_string(),
                attach_rc: None,
                attach_error: None,
            };
            let result = json_contract::JsonResult {
                ok: false,
                rc: None,
                exit_code: Some(1),
                normalized_outcome: None,
                errno: None,
                error: Some(err),
                stderr: None,
                stdout: None,
            };
            if let Err(err) =
                json_contract::print_envelope("inspector_report", result, &data)
            {
                eprintln!("{err}");
            }
            std::process::exit(1);
        }
    };

    let cs = codesign_info(&path);
    let id_ok = if let Some(id) = cs.identifier.as_ref() {
        if let Some(expected) = bundle_id.as_ref() {
            id == expected
        } else if let Some(prefix) = bundle_prefix.as_ref() {
            id.starts_with(prefix)
        } else {
            false
        }
    } else {
        false
    };

    let team_ok = cs.team_id.as_deref() == Some(team_id.as_str());
    let allowed = id_ok && team_ok && cs.rc == Some(0);

    let mut attach_attempted = false;
    let mut attach_rc: Option<i32> = None;
    let mut attach_error: Option<String> = None;
    let mut attach_result = "skipped".to_string();

    if allowed && !no_attach {
        attach_attempted = true;
        let mut task: u32 = 0;
        let rc = unsafe { task_for_pid(mach_task_self(), pid as c_int, &mut task) };
        attach_rc = Some(rc);
        if rc == 0 {
            attach_result = "ok".to_string();
            unsafe {
                mach_port_deallocate(mach_task_self(), task);
            }
        } else {
            attach_result = "refused".to_string();
            let err_ptr = unsafe { mach_error_string(rc) };
            if !err_ptr.is_null() {
                attach_error = Some(unsafe { CStr::from_ptr(err_ptr) }.to_string_lossy().to_string());
            }
        }
    }

    let data = InspectorData {
        pid,
        path: Some(path),
        identifier: cs.identifier.clone(),
        team_id: cs.team_id.clone(),
        expected_team_id: team_id.clone(),
        expected_bundle_id: bundle_id.clone(),
        expected_bundle_id_prefix: bundle_prefix.clone(),
        id_ok,
        team_ok,
        allowed,
        codesign_rc: cs.rc,
        codesign_error: cs.error.clone(),
        attach_attempted,
        attach_result: attach_result.clone(),
        attach_rc,
        attach_error: attach_error.clone(),
    };

    let exit_code = if !allowed {
        3
    } else if attach_attempted && attach_rc != Some(0) {
        4
    } else {
        0
    };

    let error = if !allowed {
        Some("identity_not_allowed".to_string())
    } else if attach_attempted && attach_rc != Some(0) {
        attach_error.clone().or_else(|| Some("attach_failed".to_string()))
    } else {
        None
    };

    let result = json_contract::JsonResult {
        ok: exit_code == 0,
        rc: None,
        exit_code: Some(exit_code),
        normalized_outcome: None,
        errno: None,
        error,
        stderr: None,
        stdout: None,
    };

    if let Err(err) = json_contract::print_envelope("inspector_report", result, &data) {
        eprintln!("{err}");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}
