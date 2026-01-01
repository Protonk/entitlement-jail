#[path = "../json_contract.rs"]
#[allow(dead_code)]
mod json_contract;

use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

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
  signpost-log-observer --correlation-id <id> [--subsystem <subsystem>] [--start <time> --end <time> | --last <duration>] [--predicate <predicate>] [--format <json|jsonl>] [--output <path>] [--plan-id <id>] [--row-id <id>]

notes:
  - runs `/usr/bin/log show --signpost --style json` and extracts signpost spans (observer-only)
  - default predicate filters on subsystem + eventMessage CONTAINS \"pw_corr=<id>\"
  - intended to run outside PolicyWitness.app (unsandboxed)"
    );
}

fn cmd_output_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches('\n').to_string()
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

fn default_predicate(subsystem: &str, correlation_id: &str) -> String {
    let escaped_subsystem = subsystem.replace('"', "\\\"");
    let term = format!("pw_corr={correlation_id}");
    let escaped_term = term.replace('"', "\\\"");
    format!(
        r#"(subsystem == "{}") AND (eventMessage CONTAINS[c] "{}")"#,
        escaped_subsystem, escaped_term
    )
}

fn truncate_bytes(bytes: &[u8]) -> (String, bool) {
    if bytes.len() <= MAX_CAPTURE_BYTES {
        return (cmd_output_to_string(bytes), false);
    }
    let mut truncated = bytes[..MAX_CAPTURE_BYTES].to_vec();
    truncated.extend_from_slice(b"\n[truncated]\n");
    (cmd_output_to_string(&truncated), true)
}

fn extract_str<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(v) = value.get(key).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    None
}

fn extract_i64(value: &serde_json::Value, keys: &[&str]) -> Option<i64> {
    for key in keys {
        if let Some(v) = value.get(key).and_then(|v| v.as_i64()) {
            return Some(v);
        }
        if let Some(v) = value.get(key).and_then(|v| v.as_str()) {
            if let Ok(parsed) = v.parse::<i64>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn extract_u64(value: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    extract_i64(value, keys).and_then(|v| u64::try_from(v).ok())
}

fn extract_signpost_id(value: &serde_json::Value) -> Option<String> {
    for key in ["signpostID", "signpostId", "signpost_id", "signpostIdentifier", "signpost_identifier"] {
        if let Some(v) = value.get(key) {
            if let Some(i) = v.as_i64() {
                return Some(i.to_string());
            }
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn extract_signpost_type(value: &serde_json::Value) -> Option<String> {
    extract_str(value, &["signpostType", "signpost_type", "signpostEventType", "signpost_event_type"])
        .map(|s| s.to_string())
}

fn extract_monotonic_ns(value: &serde_json::Value) -> Option<u64> {
    extract_u64(
        value,
        &[
            "machContinuousTime",
            "mach_continuous_time",
            "machTimestamp",
            "mach_timestamp",
            "timeSinceBootNanoseconds",
            "time_since_boot_nanoseconds",
        ],
    )
}

fn extract_pid(value: &serde_json::Value) -> Option<i64> {
    extract_i64(value, &["processID", "processId", "processIdentifier", "process_identifier", "pid"])
}

fn extract_label_from_message(message: &str) -> Option<String> {
    // The Swift signpost helper emits: "pw_corr=<id> label=<label>".
    let idx = message.find("label=")?;
    Some(message[idx + "label=".len()..].trim().to_string())
}

fn extract_corr_from_message(message: &str) -> Option<String> {
    let idx = message.find("pw_corr=")?;
    let rest = &message[idx + "pw_corr=".len()..];
    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[derive(Clone, Debug)]
struct BeginEntry {
    process: Option<String>,
    pid: Option<i64>,
    thread_id: Option<String>,
    subsystem: Option<String>,
    category: Option<String>,
    signpost_name: Option<String>,
    signpost_id: String,
    monotonic_ns: Option<u64>,
    timestamp: Option<String>,
    event_message: Option<String>,
}

#[derive(Serialize)]
struct SignpostSpan {
    process: Option<String>,
    pid: Option<i64>,
    thread_id: Option<String>,
    subsystem: Option<String>,
    category: Option<String>,
    signpost_name: Option<String>,
    signpost_id: String,
    correlation_id: Option<String>,
    label: Option<String>,
    begin_timestamp: Option<String>,
    end_timestamp: Option<String>,
    duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct ObserverLayerAttribution {
    seatbelt: String,
}

#[derive(Serialize)]
struct SignpostObserverData {
    observer_schema_version: u32,
    mode: String,
    plan_id: Option<String>,
    row_id: Option<String>,
    correlation_id: String,
    subsystem: String,
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
    parsed_json_lines: usize,
    spans: Vec<SignpostSpan>,
    unmatched_begin: usize,
    unmatched_end: usize,
    layer_attribution: ObserverLayerAttribution,
}

fn parse_spans(stdout: &str) -> (usize, usize, Vec<SignpostSpan>, usize, usize) {
    let mut parsed_json_lines = 0usize;
    let mut begins: HashMap<String, BeginEntry> = HashMap::new();
    let mut spans: Vec<SignpostSpan> = Vec::new();
    let mut unmatched_end = 0usize;

    fn process_record(
        value: &serde_json::Value,
        begins: &mut HashMap<String, BeginEntry>,
        spans: &mut Vec<SignpostSpan>,
        unmatched_end: &mut usize,
    ) {
        let Some(signpost_id) = extract_signpost_id(value) else {
            return;
        };
        let Some(signpost_type) = extract_signpost_type(value) else {
            return;
        };

        let process =
            extract_str(value, &["process", "processName", "process_name"]).map(|s| s.to_string());
        let pid = extract_pid(value);
        let thread_id = extract_str(value, &["threadID", "threadId", "thread_id"]).map(|s| s.to_string());
        let subsystem = extract_str(value, &["subsystem"]).map(|s| s.to_string());
        let category = extract_str(value, &["category"]).map(|s| s.to_string());
        let signpost_name = extract_str(value, &["signpostName", "signpost_name", "name"]).map(|s| s.to_string());
        let timestamp = extract_str(value, &["timestamp", "time"]).map(|s| s.to_string());
        let event_message = extract_str(value, &["eventMessage", "message"]).map(|s| s.to_string());
        let monotonic_ns = extract_monotonic_ns(value);

        let key = match (pid, &signpost_id) {
            (Some(pid), sid) => format!("{pid}:{sid}"),
            (None, sid) => sid.to_string(),
        };

        let typ = signpost_type.to_ascii_lowercase();
        if typ.contains("begin") {
            begins.insert(
                key,
                BeginEntry {
                    process,
                    pid,
                    thread_id,
                    subsystem,
                    category,
                    signpost_name,
                    signpost_id,
                    monotonic_ns,
                    timestamp,
                    event_message,
                },
            );
            return;
        }

        if typ.contains("end") {
            let Some(begin) = begins.remove(&key) else {
                *unmatched_end += 1;
                return;
            };

            let (corr, label) = match (begin.event_message.as_deref(), event_message.as_deref()) {
                (Some(msg), _) => (extract_corr_from_message(msg), extract_label_from_message(msg)),
                (None, Some(msg)) => (extract_corr_from_message(msg), extract_label_from_message(msg)),
                (None, None) => (None, None),
            };

            let duration_ms = match (begin.monotonic_ns, monotonic_ns) {
                (Some(start), Some(end)) if end >= start => Some((end - start) / 1_000_000),
                _ => None,
            };

            spans.push(SignpostSpan {
                process: begin.process,
                pid: begin.pid,
                thread_id: begin.thread_id,
                subsystem: begin.subsystem,
                category: begin.category,
                signpost_name: begin.signpost_name,
                signpost_id: begin.signpost_id,
                correlation_id: corr,
                label,
                begin_timestamp: begin.timestamp,
                end_timestamp: timestamp,
                duration_ms,
            });
        }
    }

    let trimmed_all = stdout.trim();
    if trimmed_all.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed_all) {
            if let Some(items) = value.as_array() {
                for item in items {
                    parsed_json_lines += 1;
                    process_record(item, &mut begins, &mut spans, &mut unmatched_end);
                }
            }
        }
    } else {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            parsed_json_lines += 1;
            process_record(&value, &mut begins, &mut spans, &mut unmatched_end);
        }
    }

    let unmatched_begin = begins.len();
    (parsed_json_lines, spans.len(), spans, unmatched_begin, unmatched_end)
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let mut correlation_id: Option<String> = None;
    let mut subsystem: String = "com.yourteam.policy-witness".to_string();
    let mut predicate: Option<String> = None;
    let mut start: Option<String> = None;
    let mut end: Option<String> = None;
    let mut last: Option<String> = None;
    let mut plan_id: Option<String> = None;
    let mut row_id: Option<String> = None;
    let mut output_format = OutputFormat::Json;
    let mut output_path: Option<PathBuf> = None;

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
            "--correlation-id" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) if !v.is_empty() => correlation_id = Some(v.to_string()),
                    _ => {
                        eprintln!("missing value for --correlation-id");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--subsystem" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) if !v.is_empty() => subsystem = v.to_string(),
                    _ => {
                        eprintln!("missing value for --subsystem");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--predicate" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) if !v.is_empty() => predicate = Some(v.to_string()),
                    _ => {
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
                    Some(v) if !v.is_empty() => start = Some(v.to_string()),
                    _ => {
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
                    Some(v) if !v.is_empty() => end = Some(v.to_string()),
                    _ => {
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
                    Some(v) if !v.is_empty() => last = Some(v.to_string()),
                    _ => {
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
                    Some(v) if !v.is_empty() => plan_id = Some(v.to_string()),
                    _ => {
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
                    Some(v) if !v.is_empty() => row_id = Some(v.to_string()),
                    _ => {
                        eprintln!("missing value for --row-id");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            "--format" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str()).unwrap_or_default();
                output_format = match OutputFormat::parse(value) {
                    Some(v) => v,
                    None => {
                        eprintln!("invalid value for --format: {value}");
                        print_usage();
                        std::process::exit(2);
                    }
                };
                idx += 2;
            }
            "--output" => {
                let value = args.get(idx + 1).and_then(|s| s.to_str());
                match value {
                    Some(v) if !v.is_empty() => output_path = Some(PathBuf::from(v)),
                    _ => {
                        eprintln!("missing value for --output");
                        print_usage();
                        std::process::exit(2);
                    }
                }
                idx += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let correlation_id = correlation_id.unwrap_or_else(|| {
        eprintln!("missing --correlation-id");
        print_usage();
        std::process::exit(2);
    });

    if (start.is_some() && end.is_none()) || (start.is_none() && end.is_some()) {
        eprintln!("--start and --end must be used together");
        print_usage();
        std::process::exit(2);
    }

    let predicate = predicate.unwrap_or_else(|| default_predicate(&subsystem, &correlation_id));

    let mut log_args: Vec<String> = vec![
        "show".to_string(),
        "--style".to_string(),
        "json".to_string(),
        "--signpost".to_string(),
        "--info".to_string(),
        "--debug".to_string(),
        "--predicate".to_string(),
        predicate.clone(),
    ];
    if let (Some(start), Some(end)) = (start.as_ref(), end.as_ref()) {
        log_args.push("--start".to_string());
        log_args.push(start.clone());
        log_args.push("--end".to_string());
        log_args.push(end.clone());
    } else if let Some(last) = last.as_ref() {
        log_args.push("--last".to_string());
        log_args.push(last.clone());
    } else {
        log_args.push("--last".to_string());
        log_args.push("30s".to_string());
        last = Some("30s".to_string());
    }

    let output = Command::new("/usr/bin/log")
        .args(&log_args)
        .output()
        .map_err(|e| format!("spawn failed for /usr/bin/log: {e}"));

    let (log_rc, stdout, stderr, log_error, log_truncated) = match output {
        Ok(output) => {
            let rc = output.status.code().unwrap_or(1);
            let (stdout, stdout_truncated) = truncate_bytes(&output.stdout);
            let (stderr, stderr_truncated) = truncate_bytes(&output.stderr);
            let truncated = stdout_truncated || stderr_truncated;
            (Some(rc), stdout, stderr, None, truncated)
        }
        Err(err) => (None, "".to_string(), "".to_string(), Some(err), false),
    };

    let observed_lines = stdout.lines().filter(|l| !l.trim().is_empty()).count();
    let (parsed_json_lines, _span_count, spans, unmatched_begin, unmatched_end) = parse_spans(&stdout);

    let data = SignpostObserverData {
        observer_schema_version: OBSERVER_SCHEMA_VERSION,
        mode: "show".to_string(),
        plan_id,
        row_id,
        correlation_id: correlation_id.clone(),
        subsystem: subsystem.clone(),
        predicate,
        start,
        end,
        last,
        log_rc,
        log_stdout: stdout,
        log_stderr: stderr,
        log_error,
        log_truncated,
        observed_lines,
        parsed_json_lines,
        spans,
        unmatched_begin,
        unmatched_end,
        layer_attribution: ObserverLayerAttribution {
            seatbelt: "observer_only".to_string(),
        },
    };

    let ok = data.log_error.is_none() && data.log_rc == Some(0);
    let result = json_contract::JsonResult::from_ok(ok);

    match output_format {
        OutputFormat::Json => {
            let text = match json_contract::render_envelope("signpost_log_observer_report", result, &data)
            {
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
                "signpost_log_observer_report",
                result,
                &data,
            ) {
                Ok(text) => text,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            let mut output_file = match output_path.as_ref() {
                Some(path) => Some(open_output(path, true).unwrap_or_else(|err| {
                    eprintln!("{err}");
                    std::process::exit(1);
                })),
                None => None,
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
    use super::{default_predicate, parse_spans};

    #[test]
    fn predicate_includes_subsystem_and_corr_term() {
        let pred = default_predicate("com.example", "abc");
        assert!(pred.contains("subsystem == \"com.example\""));
        assert!(pred.contains("pw_corr=abc"));
    }

    #[test]
    fn parses_simple_begin_end_pair() {
        let stdout = r#"
{"process":"svc","processID":123,"subsystem":"com.yourteam.policy-witness","category":"xpc_service","signpostName":"run_probe","signpostType":"begin","signpostID":1,"machTimestamp":1000,"timestamp":"t0","eventMessage":"pw_corr=abc label=run"}
{"process":"svc","processID":123,"subsystem":"com.yourteam.policy-witness","category":"xpc_service","signpostName":"run_probe","signpostType":"end","signpostID":1,"machTimestamp":2000,"timestamp":"t1","eventMessage":"pw_corr=abc label=run"}
"#;
        let (_parsed_json_lines, _span_count, spans, unmatched_begin, unmatched_end) =
            parse_spans(stdout);
        assert_eq!(unmatched_begin, 0);
        assert_eq!(unmatched_end, 0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pid, Some(123));
        assert_eq!(spans[0].signpost_name.as_deref(), Some("run_probe"));
        assert_eq!(spans[0].correlation_id.as_deref(), Some("abc"));
        assert_eq!(spans[0].label.as_deref(), Some("run"));
        assert_eq!(spans[0].duration_ms, Some(0));
    }

    #[test]
    fn parses_json_array_output() {
        let stdout = r#"[{"process":"svc","processID":123,"subsystem":"com.yourteam.policy-witness","category":"xpc_service","signpostName":"run_probe","signpostType":"begin","signpostID":1,"machTimestamp":1000,"timestamp":"t0","eventMessage":"pw_corr=abc label=run"},{"process":"svc","processID":123,"subsystem":"com.yourteam.policy-witness","category":"xpc_service","signpostName":"run_probe","signpostType":"end","signpostID":1,"machTimestamp":2000,"timestamp":"t1","eventMessage":"pw_corr=abc label=run"}]"#;
        let (parsed_json_lines, _span_count, spans, unmatched_begin, unmatched_end) =
            parse_spans(stdout);
        assert_eq!(parsed_json_lines, 2);
        assert_eq!(unmatched_begin, 0);
        assert_eq!(unmatched_end, 0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pid, Some(123));
        assert_eq!(spans[0].signpost_name.as_deref(), Some("run_probe"));
    }
}
