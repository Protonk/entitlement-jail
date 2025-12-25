#[path = "../json_contract.rs"]
#[allow(dead_code)]
mod json_contract;

use serde::Serialize;
use std::ffi::OsString;
use std::process::Command;

fn print_usage() {
    eprintln!(
        "\
usage:
  sandbox-log-observer --pid <pid> --process-name <name> [--start <time> --end <time> | --last <duration>] [--predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>]

notes:
  - runs `log show` with a sandbox-deny predicate (observer-only)
  - intended to run outside EntitlementJail.app (unsandboxed)"
    );
}

fn cmd_output_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches('\n').to_string()
}

fn sandbox_predicate(process_name: &str, pid: i32) -> String {
    let term = format!("Sandbox: {}({})", process_name, pid);
    let escaped = term.replace('"', "\\\"");
    format!(
        r#"((eventMessage CONTAINS[c] "{}") OR ((eventMessage CONTAINS[c] "deny") AND (eventMessage CONTAINS[c] "{}")))"#,
        escaped, pid
    )
}

#[derive(Serialize)]
struct ObserverLayerAttribution {
    seatbelt: String,
}

#[derive(Serialize)]
struct LogObserverData {
    plan_id: Option<String>,
    row_id: Option<String>,
    correlation_id: Option<String>,
    pid: i32,
    process_name: Option<String>,
    predicate: String,
    start: Option<String>,
    end: Option<String>,
    last: Option<String>,
    log_rc: Option<i32>,
    log_stdout: String,
    log_stderr: String,
    log_error: Option<String>,
    observed_lines: usize,
    observed_deny: bool,
    deny_lines: Vec<String>,
    layer_attribution: ObserverLayerAttribution,
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let mut pid: Option<i32> = None;
    let mut process_name: Option<String> = None;
    let mut predicate: Option<String> = None;
    let mut start: Option<String> = None;
    let mut end: Option<String> = None;
    let mut last: Option<String> = None;
    let mut plan_id: Option<String> = None;
    let mut row_id: Option<String> = None;
    let mut correlation_id: Option<String> = None;

    let mut idx = 0usize;
    while idx < args.len() {
        let arg = args
            .get(idx)
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        match arg {
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "--pid" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value.and_then(|v| v.parse::<i32>().ok()) {
                    Some(v) => pid = Some(v),
                    None => {
                        eprintln!("invalid value for --pid");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--process-name" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => process_name = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --process-name");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--predicate" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => predicate = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --predicate");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--start" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => start = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --start");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--end" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => end = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --end");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--last" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => last = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --last");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--plan-id" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => plan_id = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --plan-id");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--row-id" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => row_id = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --row-id");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--correlation-id" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => correlation_id = Some(v.to_string()),
                    None => {
                        eprintln!("missing value for --correlation-id");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            _ => {
                eprintln!("unknown arg: {}", arg);
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let pid = match pid {
        Some(v) => v,
        None => {
            eprintln!("missing --pid");
            print_usage();
            std::process::exit(2);
        }
    };

    if (start.is_some() || end.is_some()) && last.is_some() {
        eprintln!("cannot combine --start/--end with --last");
        print_usage();
        std::process::exit(2);
    }

    if start.is_some() ^ end.is_some() {
        eprintln!("--start and --end must be provided together");
        print_usage();
        std::process::exit(2);
    }

    let predicate = match predicate {
        Some(v) => v,
        None => match process_name.as_ref() {
            Some(name) => sandbox_predicate(name, pid),
            None => {
                eprintln!("missing --process-name (required when --predicate is not set)");
                print_usage();
                std::process::exit(2);
            }
        },
    };

    let mut cmd = Command::new("/usr/bin/log");
    cmd.arg("show")
        .arg("--style")
        .arg("syslog")
        .arg("--info")
        .arg("--debug");

    let last = if start.is_none() && end.is_none() {
        Some(last.unwrap_or_else(|| "5s".to_string()))
    } else {
        last
    };

    if let Some(last) = &last {
        cmd.arg("--last").arg(last);
    } else {
        if let Some(start) = &start {
            cmd.arg("--start").arg(start);
        }
        if let Some(end) = &end {
            cmd.arg("--end").arg(end);
        }
    }

    cmd.arg("--predicate").arg(&predicate);

    let out = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            let data = LogObserverData {
                plan_id: plan_id.clone(),
                row_id: row_id.clone(),
                correlation_id: correlation_id.clone(),
                pid,
                process_name,
                predicate,
                start,
                end,
                last: last.clone(),
                log_rc: None,
                log_stdout: String::new(),
                log_stderr: String::new(),
                log_error: Some(format!("failed to run log: {err}")),
                observed_lines: 0,
                observed_deny: false,
                deny_lines: Vec::new(),
                layer_attribution: ObserverLayerAttribution {
                    seatbelt: "observer_only".to_string(),
                },
            };
            let result = json_contract::JsonResult::from_ok(false);
            if let Err(err) =
                json_contract::print_envelope("sandbox_log_observer_report", result, &data)
            {
                eprintln!("{err}");
            }
            std::process::exit(1);
        }
    };

    let rc = out.status.code();
    let stdout = cmd_output_to_string(&out.stdout);
    let stderr = cmd_output_to_string(&out.stderr);

    let observed_lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let deny_lines: Vec<String> = stdout
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("deny"))
        .map(|line| line.to_string())
        .collect();
    let observed_deny = !deny_lines.is_empty();

    let data = LogObserverData {
        plan_id,
        row_id,
        correlation_id,
        pid,
        process_name,
        predicate,
        start,
        end,
        last,
        log_rc: rc,
        log_stdout: stdout,
        log_stderr: stderr,
        log_error: if out.status.success() {
            None
        } else {
            Some("log show returned non-zero".to_string())
        },
        observed_lines,
        observed_deny,
        deny_lines,
        layer_attribution: ObserverLayerAttribution {
            seatbelt: "observer_only".to_string(),
        },
    };

    let result = json_contract::JsonResult::from_ok(out.status.success());
    if let Err(err) =
        json_contract::print_envelope("sandbox_log_observer_report", result, &data)
    {
        eprintln!("{err}");
    }
}
