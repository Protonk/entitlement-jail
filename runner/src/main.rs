use std::{env, process::Command};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    // Decide what to run – simplest: first arg is the child binary.
    if args.is_empty() {
        eprintln!("usage: entitlement-jail <cmd> [args...]");
        std::process::exit(2);
    }

    let cmd_path = PathBuf::from(&args[0]);
    let rest = &args[1..];

    let mut cmd = Command::new(&cmd_path);
    cmd.args(rest);

    // Option A: exec (replace the process, keeps stdio)
    let err = cmd.exec();
    eprintln!("exec failed: {err}");
    std::process::exit(127);
}
