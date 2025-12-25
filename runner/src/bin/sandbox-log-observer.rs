#[path = "../json_contract.rs"]
#[allow(dead_code)]
mod json_contract;

use serde::Serialize;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OBSERVER_SCHEMA_VERSION: u32 = 1;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Jsonl,
}

impl OutputFormat {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(OutputFormat::Json),
            "jsonl" => Some(OutputFormat::Jsonl),
            _ => None,
        }
    }
}

fn print_usage() {
    eprintln!(
        "\
usage:
  sandbox-log-observer --pid <pid> --process-name <name> [--start <time> --end <time> | --last <duration> | --duration <seconds> | --follow] [--predicate <predicate>] [--format <json|jsonl>] [--output <path>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>]

notes:
  - runs `log show` (default) or `log stream` (with --duration/--follow) with a sandbox-deny predicate (observer-only)
  - --format jsonl emits per-line events plus a final report line
  - intended to run outside EntitlementJail.app (unsandboxed)"
    );
}

fn cmd_output_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches('\n').to_string()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sandbox_predicate(process_name: &str, pid: i32) -> String {
    let term = format!("Sandbox: {}({})", process_name, pid);
    let escaped = term.replace('"', "\\\"");
    format!(
        r#"((eventMessage CONTAINS[c] "{}") OR ((eventMessage CONTAINS[c] "deny") AND (eventMessage CONTAINS[c] "{}")))"#,
        escaped, pid
    )
}

fn open_output(path: &Path, append: bool) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && parent != Path::new(".") {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true);
    if append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    opts.open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))
}

fn write_jsonl_line(line: &str, file: Option<&mut std::fs::File>) -> Result<(), String> {
    let mut stdout = io::stdout();
    stdout
        .write_all(line.as_bytes())
        .map_err(|e| format!("failed to write stdout: {e}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|e| format!("failed to write stdout: {e}"))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush stdout: {e}"))?;
    if let Some(file) = file {
        file.write_all(line.as_bytes())
            .map_err(|e| format!("failed to write output: {e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("failed to write output: {e}"))?;
        file.flush()
            .map_err(|e| format!("failed to flush output: {e}"))?;
    }
    Ok(())
}

fn read_to_string(mut reader: impl Read) -> String {
    let mut buf = String::new();
    let _ = reader.read_to_string(&mut buf);
    buf
}

#[derive(Serialize)]
struct ObserverLayerAttribution {
    seatbelt: String,
}

#[derive(Serialize)]
struct LogObserverData {
    observer_schema_version: u32,
    mode: String,
    duration_ms: Option<u64>,
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
    log_truncated: bool,
    observed_lines: usize,
    observed_deny: bool,
    deny_lines: Vec<String>,
    layer_attribution: ObserverLayerAttribution,
}

#[derive(Serialize)]
struct LogObserverEventData {
    observer_schema_version: u32,
    plan_id: Option<String>,
    row_id: Option<String>,
    correlation_id: Option<String>,
    pid: i32,
    process_name: Option<String>,
    predicate: String,
    observed_at_unix_ms: u64,
    line: String,
    is_deny: bool,
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
    let mut output_format = OutputFormat::Json;
    let mut output_path: Option<PathBuf> = None;
    let mut follow = false;
    let mut duration: Option<Duration> = None;

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
            "--duration" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                let parsed = value.and_then(|v| v.parse::<f64>().ok());
                match parsed {
                    Some(secs) if secs > 0.0 => {
                        duration = Some(Duration::from_secs_f64(secs));
                    }
                    _ => {
                        eprintln!("invalid value for --duration (expected seconds > 0)");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--follow" => {
                follow = true;
                idx += 1;
            }
            "--format" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value.and_then(OutputFormat::parse) {
                    Some(v) => output_format = v,
                    None => {
                        eprintln!("invalid value for --format (expected json|jsonl)");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--output" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) => output_path = Some(PathBuf::from(v)),
                    None => {
                        eprintln!("missing value for --output");
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

    if follow && duration.is_some() {
        eprintln!("cannot combine --follow with --duration");
        print_usage();
        std::process::exit(2);
    }

    let stream_mode = follow || duration.is_some();

    if stream_mode && (start.is_some() || end.is_some() || last.is_some()) {
        eprintln!("--start/--end/--last cannot be combined with --duration/--follow");
        print_usage();
        std::process::exit(2);
    }

    if !stream_mode {
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

        if start.is_none() && end.is_none() {
            last = Some(last.unwrap_or_else(|| "5s".to_string()));
        }
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

    let mut output_file = if output_format == OutputFormat::Jsonl {
        output_path.as_ref().map(|path| {
            open_output(path, true).unwrap_or_else(|err| {
                eprintln!("{err}");
                std::process::exit(1);
            })
        })
    } else {
        None
    };

    let mut observed_lines = 0usize;
    let mut deny_lines: Vec<String> = Vec::new();
    let mut log_stdout = String::new();
    let mut log_stdout_bytes = 0usize;
    let mut log_truncated = false;
    let log_stderr: String;
    let log_rc: Option<i32>;
    let mut log_error: Option<String> = None;

    let mode = if stream_mode { "stream" } else { "show" }.to_string();
    let duration_ms = duration.map(|d| d.as_millis() as u64);

    if stream_mode {
        let mut cmd = Command::new("/usr/bin/log");
        cmd.arg("stream")
            .arg("--style")
            .arg("syslog")
            .arg("--info")
            .arg("--debug")
            .arg("--predicate")
            .arg(&predicate)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                let data = LogObserverData {
                    observer_schema_version: OBSERVER_SCHEMA_VERSION,
                    mode,
                    duration_ms,
                    plan_id: plan_id.clone(),
                    row_id: row_id.clone(),
                    correlation_id: correlation_id.clone(),
                    pid,
                    process_name: process_name.clone(),
                    predicate,
                    start,
                    end,
                    last,
                    log_rc: None,
                    log_stdout: String::new(),
                    log_stderr: String::new(),
                    log_error: Some(format!("failed to run log: {err}")),
                    log_truncated: false,
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

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                eprintln!("failed to capture log stdout");
                std::process::exit(1);
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                eprintln!("failed to capture log stderr");
                std::process::exit(1);
            }
        };

        let child = Arc::new(Mutex::new(child));

        if let Some(duration) = duration {
            let child_for_timer = Arc::clone(&child);
            thread::spawn(move || {
                thread::sleep(duration);
                if let Ok(mut child) = child_for_timer.lock() {
                    let _ = child.kill();
                }
            });
        }

        if follow {
            let child_for_signal = Arc::clone(&child);
            let _ = ctrlc::set_handler(move || {
                if let Ok(mut child) = child_for_signal.lock() {
                    let _ = child.kill();
                }
            });
        }

        let stderr_handle = thread::spawn(move || read_to_string(stderr));

        let mut stdout_reader = io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = match stdout_reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => break,
            };
            if bytes == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                continue;
            }
            observed_lines += 1;
            let is_deny = trimmed.to_ascii_lowercase().contains("deny");
            if is_deny {
                deny_lines.push(trimmed.to_string());
            }
            if !log_truncated {
                let add_bytes = trimmed.len() + 1;
                if log_stdout_bytes + add_bytes > MAX_CAPTURE_BYTES {
                    log_truncated = true;
                } else {
                    log_stdout.push_str(trimmed);
                    log_stdout.push('\n');
                    log_stdout_bytes += add_bytes;
                }
            }

            if output_format == OutputFormat::Jsonl {
                let event = LogObserverEventData {
                    observer_schema_version: OBSERVER_SCHEMA_VERSION,
                    plan_id: plan_id.clone(),
                    row_id: row_id.clone(),
                    correlation_id: correlation_id.clone(),
                    pid,
                    process_name: process_name.clone(),
                    predicate: predicate.clone(),
                    observed_at_unix_ms: now_unix_ms(),
                    line: trimmed.to_string(),
                    is_deny,
                };
                let text = match json_contract::render_envelope_compact(
                    "sandbox_log_observer_event",
                    json_contract::JsonResult::from_ok(true),
                    &event,
                ) {
                    Ok(text) => text,
                    Err(err) => {
                        eprintln!("{err}");
                        continue;
                    }
                };
                if let Err(err) = write_jsonl_line(&text, output_file.as_mut()) {
                    eprintln!("{err}");
                }
            }
        }

        let status = match child.lock() {
            Ok(mut child) => child.wait().ok(),
            Err(_) => None,
        };
        log_rc = status.and_then(|s| s.code());
        log_stderr = stderr_handle.join().unwrap_or_default();

        if let Some(status) = status {
            if !status.success() && duration.is_none() && !follow {
                log_error = Some("log stream returned non-zero".to_string());
            }
        }
    } else {
        let mut cmd = Command::new("/usr/bin/log");
        cmd.arg("show")
            .arg("--style")
            .arg("syslog")
            .arg("--info")
            .arg("--debug");

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
                    observer_schema_version: OBSERVER_SCHEMA_VERSION,
                    mode,
                    duration_ms,
                    plan_id: plan_id.clone(),
                    row_id: row_id.clone(),
                    correlation_id: correlation_id.clone(),
                    pid,
                    process_name: process_name.clone(),
                    predicate,
                    start,
                    end,
                    last,
                    log_rc: None,
                    log_stdout: String::new(),
                    log_stderr: String::new(),
                    log_error: Some(format!("failed to run log: {err}")),
                    log_truncated: false,
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

        log_rc = out.status.code();
        log_stdout = cmd_output_to_string(&out.stdout);
        log_stderr = cmd_output_to_string(&out.stderr);

        observed_lines = log_stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        deny_lines = log_stdout
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("deny"))
            .map(|line| line.to_string())
            .collect();

        if !out.status.success() {
            log_error = Some("log show returned non-zero".to_string());
        }
    }

    if log_error.is_none() {
        let lower = format!("{log_stdout}\n{log_stderr}").to_ascii_lowercase();
        if lower.contains("cannot run while sandboxed") {
            log_error = Some("Cannot run while sandboxed".to_string());
        }
    }

    let observed_deny = !deny_lines.is_empty();

    let data = LogObserverData {
        observer_schema_version: OBSERVER_SCHEMA_VERSION,
        mode,
        duration_ms,
        plan_id,
        row_id,
        correlation_id,
        pid,
        process_name,
        predicate,
        start,
        end,
        last,
        log_rc,
        log_stdout,
        log_stderr,
        log_error: log_error.clone(),
        log_truncated,
        observed_lines,
        observed_deny,
        deny_lines,
        layer_attribution: ObserverLayerAttribution {
            seatbelt: "observer_only".to_string(),
        },
    };

    let result = json_contract::JsonResult::from_ok(log_error.is_none());

    match output_format {
        OutputFormat::Json => {
            let text = match json_contract::render_envelope(
                "sandbox_log_observer_report",
                result,
                &data,
            ) {
                Ok(text) => text,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            if let Some(path) = output_path.as_ref() {
                match open_output(path, false) {
                    Ok(mut file) => {
                        if let Err(err) = file.write_all(format!("{text}\n").as_bytes()) {
                            eprintln!("failed to write {}: {err}", path.display());
                            std::process::exit(1);
                        }
                    }
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(1);
                    }
                }
            }
            println!("{text}");
        }
        OutputFormat::Jsonl => {
            let text = match json_contract::render_envelope_compact(
                "sandbox_log_observer_report",
                result,
                &data,
            ) {
                Ok(text) => text,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            if let Err(err) = write_jsonl_line(&text, output_file.as_mut()) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sandbox_predicate;

    #[test]
    fn predicate_escapes_quotes_and_includes_pid() {
        let pred = sandbox_predicate("service\"name", 123);
        assert!(pred.contains("Sandbox: service\\\"name(123)"));
        assert!(pred.contains("deny"));
        assert!(pred.contains("123"));
    }
}
