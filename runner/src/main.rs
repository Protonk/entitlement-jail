mod debug_entitlements_probe;

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::{env, process::Command};
use std::path::{Component, Path, PathBuf};

fn print_usage() {
    eprintln!(
        "\
usage:
  entitlement-jail run-system <absolute-platform-binary> [args...]
  entitlement-jail run-embedded <tool-name> [args...]
  entitlement-jail run-xpc [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] <xpc-service-bundle-id> <probe-id> [probe-args...]
  entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]

notes:
  - run-system only allows platform-style paths (/bin, /usr/bin, /sbin, /usr/sbin, /usr/libexec, /System/Library)
  - run-embedded looks for signed helper tools in this app bundle (Contents/Helpers and Contents/Helpers/Probes)"
    );
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
    debug_entitlements_probe::try_dlopen_external_library();

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
        Some("run-xpc") => {
            let mut idx = 1;
            while idx < args.len() {
                match args.get(idx).and_then(|s| s.to_str()) {
                    Some("-h") | Some("--help") => {
                        print_usage();
                        return;
                    }
                    Some("--log-sandbox")
                    | Some("--log-stream")
                    | Some("--log-predicate")
                    | Some("--plan-id")
                    | Some("--row-id")
                    | Some("--correlation-id")
                    | Some("--expected-outcome") => {
                        if idx + 1 >= args.len() {
                            eprintln!("missing value for {}", args[idx].to_string_lossy());
                            print_usage();
                            std::process::exit(2);
                        }
                        idx += 2;
                    }
                    _ => break,
                }
            }
            if args.len() - idx < 2 {
                print_usage();
                std::process::exit(2);
            }
            let cmd_path = match resolve_contents_macos_tool("xpc-probe-client") {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}\n");
                    eprintln!("note: xpc mode requires the embedded `xpc-probe-client` tool under Contents/MacOS.");
                    std::process::exit(2);
                }
            };
            if let Err(err) = ensure_executable_file(&cmd_path) {
                eprintln!("{err}");
                std::process::exit(2);
            }
            run_and_wait(cmd_path, args[1..].to_vec());
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
