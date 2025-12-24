import Foundation
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "xpc-probe-client"
    fputs("usage: \(exe) [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--wait-fifo <path>|--wait-exists <path>] [--wait-path-class <class>] [--wait-name <name>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create] [--attach <seconds>] [--hold-open <seconds>] <xpc-service-bundle-id> <probe-id> [probe-args...]\n", stderr)
}

if ProcessInfo.processInfo.environment["EJ_XPC_CLIENT_DEBUG"] == "1" {
    let exePath = CommandLine.arguments.first ?? "<unknown>"
    let bundlePath = Bundle.main.bundleURL.path
    let bundleId = Bundle.main.bundleIdentifier ?? "<nil>"
    fputs("debug: exe=\(exePath)\n", stderr)
    fputs("debug: Bundle.main.bundlePath=\(bundlePath)\n", stderr)
    fputs("debug: Bundle.main.bundleIdentifier=\(bundleId)\n", stderr)
}

struct LogCaptureSpec {
    var path: String
    var predicate: String?
}

private struct ProcessRun {
    var rc: Int32
    var stdout: Data
    var stderr: Data
}

private func runProcess(_ argv: [String]) -> ProcessRun {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: argv[0])
    process.arguments = Array(argv.dropFirst())

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    do {
        try process.run()
    } catch {
        return ProcessRun(
            rc: 127,
            stdout: Data(),
            stderr: Data("spawn failed: \(error)\n".utf8)
        )
    }

    process.waitUntilExit()
    let out = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let err = stderrPipe.fileHandleForReading.readDataToEndOfFile()
    return ProcessRun(rc: process.terminationStatus, stdout: out, stderr: err)
}

private func sandboxPredicate(processName: String, pid: String) -> String {
    let term = "Sandbox: \(processName)(\(pid))"
    let escaped = term.replacingOccurrences(of: "\"", with: "\\\"")
    return #"(eventMessage CONTAINS[c] "\#(escaped)")"#
}

private func containerBaseURL(for bundleId: String) -> URL {
    let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
    return home
        .appendingPathComponent("Library", isDirectory: true)
        .appendingPathComponent("Containers", isDirectory: true)
        .appendingPathComponent(bundleId, isDirectory: true)
        .appendingPathComponent("Data", isDirectory: true)
}

private func resolveContainerPath(bundleId: String, pathClass: String, name: String) -> String? {
    let base = containerBaseURL(for: bundleId)
    let root: URL?
    switch pathClass {
    case "home":
        root = base
    case "tmp":
        root = base.appendingPathComponent("tmp", isDirectory: true)
    case "downloads":
        root = base.appendingPathComponent("Downloads", isDirectory: true)
    case "desktop":
        root = base.appendingPathComponent("Desktop", isDirectory: true)
    case "documents":
        root = base.appendingPathComponent("Documents", isDirectory: true)
    case "app_support":
        root = base.appendingPathComponent("Library", isDirectory: true).appendingPathComponent("Application Support", isDirectory: true)
    case "caches":
        root = base.appendingPathComponent("Library", isDirectory: true).appendingPathComponent("Caches", isDirectory: true)
    default:
        root = nil
    }
    return root?.appendingPathComponent(name, isDirectory: false).path
}

private func isKnownPathClass(_ cls: String) -> Bool {
    switch cls {
    case "home", "tmp", "downloads", "desktop", "documents", "app_support", "caches":
        return true
    default:
        return false
    }
}

private func isSinglePathComponent(_ s: String) -> Bool {
    if s.isEmpty || s == "." || s == ".." { return false }
    return !s.contains("/") && !s.contains("\\")
}

private func fetchSandboxLog(start: Date, end: Date, predicate: String) -> String {
    let df = DateFormatter()
    df.dateFormat = "yyyy-MM-dd HH:mm:ss"
    df.timeZone = TimeZone.current

    let startStr = df.string(from: start)
    let endStr = df.string(from: end)

    let cmd = [
        "/usr/bin/log",
        "show",
        "--style",
        "syslog",
        "--start",
        startStr,
        "--end",
        endStr,
        "--predicate",
        predicate,
    ]

    let run = runProcess(cmd)
    var out = String(data: run.stdout, encoding: .utf8) ?? ""
    let err = String(data: run.stderr, encoding: .utf8) ?? ""
    if out.isEmpty, !err.isEmpty {
        out = "log show error: \(err)"
    } else if !err.isEmpty {
        out += "\nlog show error: \(err)"
    }
    return out
}

private func writeLogCapture(path: String, contents: String) {
    let url = URL(fileURLWithPath: path)
    let parent = url.deletingLastPathComponent()
    if !parent.path.isEmpty && parent.path != "." {
        try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
    }
    do {
        try contents.write(to: url, atomically: true, encoding: .utf8)
    } catch {
        fputs("failed to write log capture: \(error)\n", stderr)
        let home = NSHomeDirectory()
        let tmp = NSTemporaryDirectory()
        fputs("hint: choose a path under \(home) or \(tmp)\n", stderr)
    }
}

private func captureSandboxLog(spec: LogCaptureSpec, response: RunProbeResponse?, serviceName: String, started: Date, ended: Date) {
    guard let response else {
        writeLogCapture(path: spec.path, contents: "log capture skipped: failed to decode response JSON\n")
        return
    }
    let details = response.details ?? [:]
    let probePid = details["probe_pid"]
    let servicePid = details["service_pid"]
    let fallbackPid = details["pid"]
    let pid = (probePid?.isEmpty == false ? probePid : (servicePid?.isEmpty == false ? servicePid : fallbackPid)) ?? ""
    guard !pid.isEmpty else {
        writeLogCapture(path: spec.path, contents: "log capture skipped: missing pid in response details\n")
        return
    }
    let processName = details["process_name"] ?? serviceName
    let predicate = spec.predicate ?? sandboxPredicate(processName: processName, pid: pid)
    let start = started.addingTimeInterval(-1)
    let end = ended.addingTimeInterval(1)
    let excerpt = fetchSandboxLog(start: start, end: end, predicate: predicate)
    writeLogCapture(path: spec.path, contents: excerpt)
}

let args = CommandLine.arguments

var logPath: String?
var logPredicate: String?
var planId: String?
var rowId: String?
var correlationId: String?
var expectedOutcome: String?
var holdOpenSeconds: TimeInterval?
var waitMode: String?
var waitPath: String?
var waitPathClass: String?
var waitName: String?
var waitTimeoutMs: Int?
var waitIntervalMs: Int?
var waitCreate: Bool?
var attachSeconds: TimeInterval?

var idx = 1
parseLoop: while idx < args.count {
    let a = args[idx]
    switch a {
    case "-h", "--help":
        printUsage()
        exit(0)
    case "--log-sandbox", "--log-stream":
        guard idx + 1 < args.count else {
            fputs("missing value for \(a)\n", stderr)
            printUsage()
            exit(2)
        }
        logPath = args[idx + 1]
        idx += 2
    case "--log-predicate":
        guard idx + 1 < args.count else {
            fputs("missing value for --log-predicate\n", stderr)
            printUsage()
            exit(2)
        }
        logPredicate = args[idx + 1]
        idx += 2
    case "--plan-id":
        guard idx + 1 < args.count else {
            fputs("missing value for --plan-id\n", stderr)
            printUsage()
            exit(2)
        }
        planId = args[idx + 1]
        idx += 2
    case "--row-id":
        guard idx + 1 < args.count else {
            fputs("missing value for --row-id\n", stderr)
            printUsage()
            exit(2)
        }
        rowId = args[idx + 1]
        idx += 2
    case "--correlation-id":
        guard idx + 1 < args.count else {
            fputs("missing value for --correlation-id\n", stderr)
            printUsage()
            exit(2)
        }
        correlationId = args[idx + 1]
        idx += 2
    case "--expected-outcome":
        guard idx + 1 < args.count else {
            fputs("missing value for --expected-outcome\n", stderr)
            printUsage()
            exit(2)
        }
        expectedOutcome = args[idx + 1]
        idx += 2
    case "--hold-open":
        guard idx + 1 < args.count else {
            fputs("missing value for --hold-open\n", stderr)
            printUsage()
            exit(2)
        }
        let raw = args[idx + 1]
        guard let secs = Double(raw), secs >= 0 else {
            fputs("invalid value for --hold-open (expected seconds >= 0)\n", stderr)
            printUsage()
            exit(2)
        }
        holdOpenSeconds = secs
        idx += 2
    case "--wait-fifo":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-fifo\n", stderr)
            printUsage()
            exit(2)
        }
        if let waitMode, waitMode != "fifo" {
            fputs("cannot combine --wait-fifo with --wait-exists\n", stderr)
            printUsage()
            exit(2)
        }
        waitMode = "fifo"
        waitPath = args[idx + 1]
        idx += 2
    case "--wait-exists":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-exists\n", stderr)
            printUsage()
            exit(2)
        }
        if let waitMode, waitMode != "exists" {
            fputs("cannot combine --wait-exists with --wait-fifo\n", stderr)
            printUsage()
            exit(2)
        }
        waitMode = "exists"
        waitPath = args[idx + 1]
        idx += 2
    case "--wait-path-class":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-path-class\n", stderr)
            printUsage()
            exit(2)
        }
        waitPathClass = args[idx + 1]
        idx += 2
    case "--wait-name":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-name\n", stderr)
            printUsage()
            exit(2)
        }
        waitName = args[idx + 1]
        idx += 2
    case "--wait-timeout-ms":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-timeout-ms\n", stderr)
            printUsage()
            exit(2)
        }
        guard let v = Int(args[idx + 1]), v >= 0 else {
            fputs("invalid value for --wait-timeout-ms (expected >= 0)\n", stderr)
            printUsage()
            exit(2)
        }
        waitTimeoutMs = v
        idx += 2
    case "--wait-interval-ms":
        guard idx + 1 < args.count else {
            fputs("missing value for --wait-interval-ms\n", stderr)
            printUsage()
            exit(2)
        }
        guard let v = Int(args[idx + 1]), v >= 1 else {
            fputs("invalid value for --wait-interval-ms (expected >= 1)\n", stderr)
            printUsage()
            exit(2)
        }
        waitIntervalMs = v
        idx += 2
    case "--wait-create":
        waitCreate = true
        idx += 1
    case "--attach":
        guard idx + 1 < args.count else {
            fputs("missing value for --attach\n", stderr)
            printUsage()
            exit(2)
        }
        let raw = args[idx + 1]
        guard let secs = Double(raw), secs > 0 else {
            fputs("invalid value for --attach (expected seconds > 0)\n", stderr)
            printUsage()
            exit(2)
        }
        attachSeconds = secs
        idx += 2
    default:
        break parseLoop
    }
}

if logPredicate != nil && logPath == nil {
    fputs("missing value for --log-sandbox/--log-stream (required when --log-predicate is set)\n", stderr)
    printUsage()
    exit(2)
}

guard args.count - idx >= 2 else {
    printUsage()
    exit(2)
}

let serviceName = args[idx]
let probeId = args[idx + 1]
let probeArgs = Array(args.dropFirst(idx + 2))

let logSpec = logPath.map { LogCaptureSpec(path: $0, predicate: logPredicate) }

if correlationId == nil {
    correlationId = UUID().uuidString
}

if let attachSeconds {
    if holdOpenSeconds == nil {
        holdOpenSeconds = attachSeconds
    }
    if waitMode == nil {
        waitMode = "fifo"
    }
    if waitTimeoutMs == nil {
        waitTimeoutMs = Int(attachSeconds * 1000.0)
    }
    if waitPath == nil && waitPathClass == nil {
        waitPathClass = "tmp"
    }
    if waitName == nil && waitPath == nil {
        let seed = correlationId ?? UUID().uuidString
        let candidate = "ej-attach-\(seed).fifo"
        waitName = isSinglePathComponent(candidate) ? candidate : "ej-attach-\(UUID().uuidString).fifo"
    }
    if waitCreate == nil && (waitMode == nil || waitMode == "fifo") {
        waitCreate = true
    }
}

if waitMode == nil {
    if waitPath != nil || waitPathClass != nil || waitName != nil || waitTimeoutMs != nil || waitIntervalMs != nil || waitCreate != nil {
        fputs("missing --wait-fifo/--wait-exists (required when wait options are provided)\n", stderr)
        printUsage()
        exit(2)
    }
} else {
    guard waitMode == "fifo" || waitMode == "exists" else {
        fputs("invalid wait mode (expected fifo or exists)\n", stderr)
        printUsage()
        exit(2)
    }
    if waitPath != nil && (waitPathClass != nil || waitName != nil) {
        fputs("--wait-path-class/--wait-name cannot be combined with an explicit wait path\n", stderr)
        printUsage()
        exit(2)
    }
    if let waitPath, !waitPath.hasPrefix("/") {
        fputs("wait path must be absolute\n", stderr)
        printUsage()
        exit(2)
    }
    if let waitPathClass {
        guard isKnownPathClass(waitPathClass) else {
            fputs("invalid --wait-path-class (expected home|tmp|downloads|desktop|documents|app_support|caches)\n", stderr)
            printUsage()
            exit(2)
        }
        guard let waitName, isSinglePathComponent(waitName) else {
            fputs("invalid --wait-name (must be a single path component)\n", stderr)
            printUsage()
            exit(2)
        }
    }
    if waitPath == nil && waitPathClass == nil {
        fputs("missing wait path (use --wait-fifo/--wait-exists <path> or --wait-path-class + --wait-name)\n", stderr)
        printUsage()
        exit(2)
    }
    if waitCreate == true && waitMode != "fifo" {
        fputs("--wait-create is only valid with --wait-fifo\n", stderr)
        printUsage()
        exit(2)
    }
}

let waitSpec: WaitSpec? = {
    guard let waitMode else { return nil }
    return WaitSpec(
        mode: waitMode,
        path: waitPath,
        path_class: waitPathClass,
        name: waitName,
        timeout_ms: waitTimeoutMs,
        interval_ms: waitIntervalMs,
        create: waitCreate
    )
}()

if let waitMode {
    let waitPathForPrint = waitPath ?? (waitPathClass.flatMap { cls in
        waitName.flatMap { name in
            resolveContainerPath(bundleId: serviceName, pathClass: cls, name: name)
        }
    })
    if let waitPathForPrint {
        fputs("[client] wait-ready mode=\(waitMode) wait_path=\(waitPathForPrint)\n", stderr)
    } else if let waitPathClass, let waitName {
        fputs("[client] wait-ready mode=\(waitMode) wait_path_class=\(waitPathClass) wait_name=\(waitName)\n", stderr)
    }
}

let request = RunProbeRequest(
    plan_id: planId,
    row_id: rowId,
    correlation_id: correlationId,
    probe_id: probeId,
    argv: probeArgs,
    expected_outcome: expectedOutcome,
    env_overrides: nil,
    wait_spec: waitSpec
)
let requestData: Data
do {
    requestData = try encodeJSON(request)
} catch {
    fputs("failed to encode request JSON: \(error)\n", stderr)
    exit(2)
}

let connection = NSXPCConnection(serviceName: serviceName)
connection.remoteObjectInterface = NSXPCInterface(with: ProbeServiceProtocol.self)
connection.resume()

let semaphore = DispatchSemaphore(value: 0)
var exitCode: Int32 = 1

guard
    let proxy = connection.remoteObjectProxyWithErrorHandler({ err in
        fputs("xpc connection error: \(err)\n", stderr)
        semaphore.signal()
    }) as? ProbeServiceProtocol
else {
    fputs("failed to create xpc proxy\n", stderr)
    exit(1)
}

let started = Date()
proxy.runProbe(requestData) { responseData in
    let ended = Date()
    if let json = String(data: responseData, encoding: .utf8) {
        print(json)
    } else {
        fputs("service returned non-utf8 response\n", stderr)
    }

    var decodedResponse: RunProbeResponse?
    do {
        let response = try decodeJSON(RunProbeResponse.self, from: responseData)
        decodedResponse = response
        exitCode = Int32(clamping: response.rc)
    } catch {
        fputs("failed to decode response JSON: \(error)\n", stderr)
        exitCode = 1
    }

    if let spec = logSpec {
        captureSandboxLog(spec: spec, response: decodedResponse, serviceName: serviceName, started: started, ended: ended)
    }
    if let hold = holdOpenSeconds, hold > 0 {
        Thread.sleep(forTimeInterval: hold)
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
connection.invalidate()
exit(exitCode)
