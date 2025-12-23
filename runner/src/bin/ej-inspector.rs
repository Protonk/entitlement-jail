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
            let json = format!(
                "{{\"pid\":{},\"path\":null,\"error\":\"{}\"}}",
                pid,
                json_escape(&err)
            );
            println!("{json}");
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

    let json = format!(
        "{{\
\"pid\":{},\
\"path\":\"{}\",\
\"identifier\":{},\
\"team_id\":{},\
\"expected_team_id\":\"{}\",\
\"expected_bundle_id\":{},\
\"expected_bundle_id_prefix\":{},\
\"id_ok\":{},\
\"team_ok\":{},\
\"allowed\":{},\
\"codesign_rc\":{},\
\"codesign_error\":{},\
\"attach_attempted\":{},\
\"attach_result\":\"{}\",\
\"attach_rc\":{},\
\"attach_error\":{}\
}}",
        pid,
        json_escape(&path),
        cs.identifier
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string()),
        cs.team_id
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string()),
        json_escape(&team_id),
        bundle_id
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string()),
        bundle_prefix
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string()),
        if id_ok { "true" } else { "false" },
        if team_ok { "true" } else { "false" },
        if allowed { "true" } else { "false" },
        cs.rc
            .map(|rc| rc.to_string())
            .unwrap_or("null".to_string()),
        cs.error
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string()),
        if attach_attempted { "true" } else { "false" },
        attach_result,
        attach_rc
            .map(|rc| rc.to_string())
            .unwrap_or("null".to_string()),
        attach_error
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or("null".to_string())
    );

    println!("{json}");

    if !allowed {
        std::process::exit(3);
    }
    if attach_attempted && attach_rc != Some(0) {
        std::process::exit(4);
    }
}
