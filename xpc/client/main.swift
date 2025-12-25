import Foundation
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "xpc-probe-client"
    fputs("usage: \(exe) [--log-stream <path>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--wait-fifo <path>|--wait-exists <path>|--wait-path-class <class> --wait-name <name>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create] [--attach <seconds>] [--hold-open <seconds>] <xpc-service-bundle-id> <probe-id> [probe-args...]\n", stderr)
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
    var predicate_override: String?
}

private struct ProbeData: Encodable {
    var plan_id: String?
    var row_id: String?
    var correlation_id: String?
    var probe_id: String?
    var argv: [String]?
    var expected_outcome: String?
    var service_bundle_id: String?
    var service_name: String?
    var service_version: String?
    var service_build: String?
    var started_at_iso8601: String?
    var ended_at_iso8601: String?
    var thread_id: String?
    var details: [String: String]?
    var layer_attribution: LayerAttribution?
    var sandbox_log_excerpt_ref: String?
    var log_capture_status: String?
    var log_capture_path: String?
    var log_capture_error: String?
    var log_capture_predicate: String?
    var log_capture_observed_lines: Int?
    var log_capture_observed_deny: Bool?
    var log_observer_status: String?
    var log_observer_error: String?
    var log_observer_path: String?
    var log_observer_predicate: String?
    var log_observer_start: String?
    var log_observer_end: String?
    var log_observer_last: String?
    var log_observer_observed_lines: Int?
    var log_observer_observed_deny: Bool?
    var log_observer_deny_lines: [String]?
    var deny_evidence: String?
}

private struct DecodeFailureData: Encodable {
    var raw_response: String?
    var decode_error: String
}

private struct ProcessRun {
    var rc: Int32
    var stdout: Data
    var stderr: Data
}

private func runCommand(_ argv: [String]) -> ProcessRun {
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

private struct LogCaptureSummary {
    var status: String
    var error: String?
    var denyEvidence: String?
    var observedLines: Int?
    var observedDeny: Bool?
    var predicate: String?
}

private struct ObserverSummary {
    var status: String
    var error: String?
    var path: String?
    var predicate: String?
    var start: String?
    var end: String?
    var last: String?
    var observedLines: Int?
    var observedDeny: Bool?
    var denyLines: [String]?
}

private struct LogStreamLayerAttribution: Encodable {
    var seatbelt: String
}

private struct LogStreamReportData: Encodable {
    var pid: String?
    var process_name: String?
    var predicate: String?
    var log_rc: Int?
    var log_stdout: String
    var log_stderr: String
    var log_error: String?
    var observed_lines: Int
    var observed_deny: Bool
    var layer_attribution: LogStreamLayerAttribution
}

private struct ObserverReportEnvelope: Decodable {
    var kind: String?
    var result: JsonResult?
    var data: ObserverReportData?
}

private struct ObserverReportData: Decodable {
    var plan_id: String?
    var row_id: String?
    var correlation_id: String?
    var pid: Int?
    var process_name: String?
    var predicate: String?
    var start: String?
    var end: String?
    var last: String?
    var log_rc: Int?
    var log_stdout: String?
    var log_stderr: String?
    var log_error: String?
    var observed_lines: Int?
    var observed_deny: Bool?
    var deny_lines: [String]?
}

private func sandboxPredicate(processName: String, pid: String) -> String {
    let escapedPid = pid.replacingOccurrences(of: "\"", with: "\\\"")
    let escapedName = processName.replacingOccurrences(of: "\"", with: "\\\"")
    let strictTerm = "Sandbox: \(escapedName)(\(escapedPid))"
    return #"(eventMessage CONTAINS[c] "\#(strictTerm)") OR ((eventMessage CONTAINS[c] "deny") AND ((eventMessage CONTAINS[c] "\#(escapedPid)") OR (eventMessage CONTAINS[c] "\#(escapedName)")))"#
}

private func streamSandboxPredicate(processName: String, pid: String?) -> String {
    let escapedName = processName.replacingOccurrences(of: "\"", with: "\\\"")
    if let pid, !pid.isEmpty {
        return sandboxPredicate(processName: processName, pid: pid)
    }
    return #"(eventMessage CONTAINS[c] "Sandbox: \#(escapedName)") OR ((eventMessage CONTAINS[c] "deny") AND (eventMessage CONTAINS[c] "\#(escapedName)"))"#
}

private func containerBaseURL(for bundleId: String) -> URL {
    let homePath = hostHomeDirectory() ?? NSHomeDirectory()
    let home = URL(fileURLWithPath: homePath, isDirectory: true)
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

private func hostHomeDirectory() -> String? {
    let uid = getuid()
    guard let pwd = getpwuid(uid), let dir = pwd.pointee.pw_dir else {
        return nil
    }
    return String(cString: dir)
}

private func writeLogCapture(path: String, contents: String) -> String? {
    let url = URL(fileURLWithPath: path)
    let parent = url.deletingLastPathComponent()
    if !parent.path.isEmpty && parent.path != "." {
        try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
    }
    do {
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return nil
    } catch {
        fputs("failed to write log capture: \(error)\n", stderr)
        let home = NSHomeDirectory()
        let tmp = NSTemporaryDirectory()
        fputs("hint: choose a path under \(home) or \(tmp)\n", stderr)
        return "write_failed: \(error)"
    }
}

private func writeLogStreamReport(path: String, data: LogStreamReportData, ok: Bool) -> String? {
    let envelope = JsonEnvelope(
        kind: "sandbox_log_stream_report",
        generated_at_unix_ms: UInt64(Date().timeIntervalSince1970 * 1000.0),
        result: JsonResult(ok: ok, exit_code: ok ? 0 : 3),
        data: data
    )
    do {
        let encoded = try encodeJSON(envelope)
        let text = String(data: encoded, encoding: .utf8) ?? ""
        if text.isEmpty {
            return "failed to encode log stream report"
        }
        return writeLogCapture(path: path, contents: text)
    } catch {
        return "failed to encode log stream report: \(error)"
    }
}

private func filterLogStreamLines(_ stdout: String, pid: String, processName: String) -> [String] {
    let lowerPid = pid.lowercased()
    let lowerName = processName.lowercased()
    let pidToken = lowerPid.isEmpty ? nil : "(\(lowerPid))"
    return stdout
        .split(separator: "\n", omittingEmptySubsequences: false)
        .map(String.init)
        .filter { line in
            let lower = line.lowercased()
            if !lower.contains("deny") && !lower.contains("sandbox:") { return false }
            if let pidToken, lower.contains(pidToken) { return true }
            if !lowerPid.isEmpty && lower.contains("deny") && lower.contains(lowerPid) { return true }
            if !lowerName.isEmpty && lower.contains(lowerName) { return true }
            return false
        }
}

private struct LogStreamHandle {
    var process: Process
    var stdoutPipe: Pipe
    var stderrPipe: Pipe
    var predicate: String
}

private func startLogStream(predicate: String) -> (LogStreamHandle?, String?) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
    process.arguments = [
        "stream",
        "--style",
        "syslog",
        "--info",
        "--debug",
        "--predicate",
        predicate,
    ]

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    do {
        try process.run()
    } catch {
        return (nil, "spawn failed: \(error)")
    }

    return (LogStreamHandle(process: process, stdoutPipe: stdoutPipe, stderrPipe: stderrPipe, predicate: predicate), nil)
}

private func stopLogStream(_ handle: LogStreamHandle) -> ProcessRun {
    if handle.process.isRunning {
        handle.process.terminate()
    }
    handle.process.waitUntilExit()
    let out = handle.stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let err = handle.stderrPipe.fileHandleForReading.readDataToEndOfFile()
    return ProcessRun(rc: handle.process.terminationStatus, stdout: out, stderr: err)
}

private func serviceNameHint(from bundleId: String) -> String {
    if let last = bundleId.split(separator: ".").last, !last.isEmpty {
        return String(last)
    }
    return bundleId
}

private func connectionPidHint(_ connection: NSXPCConnection) -> String? {
    let pid = connection.processIdentifier
    return pid > 0 ? "\(pid)" : nil
}

private func parseIso8601(_ value: String?) -> Date? {
    guard let value, !value.isEmpty else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)
}

private func formatLogShowTime(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone.current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return formatter.string(from: date)
}

private func observerReportPath(for logPath: String) -> String {
    return "\(logPath).observer.json"
}

private func resolveObserverToolPath() -> String? {
    let bundleURL = Bundle.main.bundleURL
    let candidate = bundleURL
        .appendingPathComponent("Contents", isDirectory: true)
        .appendingPathComponent("MacOS", isDirectory: true)
        .appendingPathComponent("sandbox-log-observer", isDirectory: false)
    let path = candidate.path
    return FileManager.default.isExecutableFile(atPath: path) ? path : nil
}

private func captureSandboxLogStream(
    spec: LogCaptureSpec,
    stream: LogStreamHandle?,
    streamError: String?,
    response: RunProbeResponse,
    serviceName: String,
    predicate: String
) -> LogCaptureSummary {
    let details = response.details ?? [:]
    let probePid = details["probe_pid"]
    let servicePid = details["service_pid"]
    let fallbackPid = details["pid"]
    let pid = (probePid?.isEmpty == false ? probePid : (servicePid?.isEmpty == false ? servicePid : fallbackPid)) ?? ""
    let processName = details["process_name"] ?? serviceNameHint(from: serviceName)
    var logError = streamError
    var logRc: Int? = nil
    var stdout = ""
    var stderr = ""

    if let stream {
        let run = stopLogStream(stream)
        logRc = Int(run.rc)
        stdout = String(data: run.stdout, encoding: .utf8) ?? ""
        stderr = String(data: run.stderr, encoding: .utf8) ?? ""
    } else if logError == nil {
        logError = "log stream missing"
    }

    let lowerStdout = stdout.lowercased()
    let lowerStderr = stderr.lowercased()
    if lowerStdout.contains("cannot run while sandboxed") || lowerStderr.contains("cannot run while sandboxed") {
        logError = "Cannot run while sandboxed"
    }

    let matched = filterLogStreamLines(stdout, pid: pid, processName: processName)
    let logStdout = matched.joined(separator: "\n")
    let observedLines = matched.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count
    let observedDeny = matched.contains { $0.localizedCaseInsensitiveContains("deny") }

    let report = LogStreamReportData(
        pid: pid.isEmpty ? nil : pid,
        process_name: processName.isEmpty ? nil : processName,
        predicate: predicate.isEmpty ? nil : predicate,
        log_rc: logRc,
        log_stdout: logStdout,
        log_stderr: stderr,
        log_error: logError,
        observed_lines: observedLines,
        observed_deny: observedDeny,
        layer_attribution: LogStreamLayerAttribution(seatbelt: "log_stream")
    )

    let writeErr = writeLogStreamReport(path: spec.path, data: report, ok: logError == nil)

    var status = "requested_written"
    var error: String? = nil
    if let writeErr {
        status = "requested_failed"
        error = writeErr
    } else if let logError {
        status = "requested_failed"
        error = logError
    }

    let denyEvidence: String
    if logError != nil {
        denyEvidence = "log_error"
    } else if observedDeny {
        denyEvidence = "captured"
    } else {
        denyEvidence = "not_found"
    }

    return LogCaptureSummary(
        status: status,
        error: error,
        denyEvidence: denyEvidence,
        observedLines: observedLines,
        observedDeny: observedDeny,
        predicate: predicate.isEmpty ? nil : predicate
    )
}

private func captureSandboxLogObserver(
    logPath: String,
    response: RunProbeResponse,
    serviceName: String,
    predicateOverride: String?,
    planId: String?,
    rowId: String?,
    correlationId: String?,
    clientStarted: Date,
    clientEnded: Date
) -> ObserverSummary {
    let observerPath = observerReportPath(for: logPath)
    let details = response.details ?? [:]
    let probePid = details["probe_pid"]
    let servicePid = details["service_pid"]
    let fallbackPid = details["pid"]
    let pid = (probePid?.isEmpty == false ? probePid : (servicePid?.isEmpty == false ? servicePid : fallbackPid)) ?? ""
    let processName = (details["process_name"]?.isEmpty == false)
        ? (details["process_name"] ?? "")
        : serviceNameHint(from: serviceName)

    guard !pid.isEmpty else {
        return ObserverSummary(
            status: "requested_failed",
            error: "missing_pid",
            path: observerPath,
            predicate: nil,
            start: nil,
            end: nil,
            last: nil,
            observedLines: nil,
            observedDeny: nil,
            denyLines: nil
        )
    }

    guard let toolPath = resolveObserverToolPath() else {
        return ObserverSummary(
            status: "requested_failed",
            error: "observer_missing",
            path: observerPath,
            predicate: nil,
            start: nil,
            end: nil,
            last: nil,
            observedLines: nil,
            observedDeny: nil,
            denyLines: nil
        )
    }

    let startSource = parseIso8601(response.started_at_iso8601) ?? clientStarted
    let endSource = parseIso8601(response.ended_at_iso8601) ?? clientEnded
    let paddedStart = startSource.addingTimeInterval(-2)
    let paddedEnd = max(endSource.addingTimeInterval(2), paddedStart.addingTimeInterval(1))
    let startText = formatLogShowTime(paddedStart)
    let endText = formatLogShowTime(paddedEnd)

    var argv = [
        toolPath,
        "--pid",
        pid,
        "--process-name",
        processName,
        "--start",
        startText,
        "--end",
        endText,
    ]
    if let predicateOverride {
        argv.append("--predicate")
        argv.append(predicateOverride)
    }
    if let planId {
        argv.append("--plan-id")
        argv.append(planId)
    }
    if let rowId {
        argv.append("--row-id")
        argv.append(rowId)
    }
    if let correlationId {
        argv.append("--correlation-id")
        argv.append(correlationId)
    }

    let run = runCommand(argv)
    let stdout = String(data: run.stdout, encoding: .utf8) ?? ""
    let stderr = String(data: run.stderr, encoding: .utf8) ?? ""

    let writePayload: String = {
        if !stdout.isEmpty {
            return stdout
        }
        if !stderr.isEmpty {
            return "observer stderr:\n\(stderr)"
        }
        return "observer output empty\n"
    }()

    let writeErr = writeLogCapture(path: observerPath, contents: writePayload)

    var status = "requested_written"
    var error: String? = writeErr

    var observerPredicate: String? = predicateOverride
    var observerStart: String? = startText
    var observerEnd: String? = endText
    var observerLast: String? = nil
    var observedLines: Int? = nil
    var observedDeny: Bool? = nil
    var denyLines: [String]? = nil

    if let report = try? decodeJSON(ObserverReportEnvelope.self, from: run.stdout),
       let data = report.data {
        observerPredicate = data.predicate ?? observerPredicate
        observerStart = data.start ?? observerStart
        observerEnd = data.end ?? observerEnd
        observerLast = data.last ?? observerLast
        observedLines = data.observed_lines
        observedDeny = data.observed_deny
        denyLines = data.deny_lines
        if let logError = data.log_error, !logError.isEmpty {
            status = "requested_failed"
            error = logError
        } else if report.result?.ok == false {
            status = "requested_failed"
            error = error ?? "observer_report_not_ok"
        }
    } else if error == nil {
        status = "requested_failed"
        error = "observer_decode_failed"
    }

    if run.rc != 0 && error == nil {
        status = "requested_failed"
        error = "observer_exit=\(run.rc)"
    }

    return ObserverSummary(
        status: status,
        error: error,
        path: observerPath,
        predicate: observerPredicate,
        start: observerStart,
        end: observerEnd,
        last: observerLast,
        observedLines: observedLines,
        observedDeny: observedDeny,
        denyLines: denyLines
    )
}

let args = CommandLine.arguments

var logPath: String?
var logPredicate: String?
var logPathClass: String?
var logName: String?
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
    case "--log-sandbox":
        fputs("--log-sandbox has been removed; use --log-stream or sandbox-log-observer instead\n", stderr)
        printUsage()
        exit(2)
    case "--log-stream":
        guard idx + 1 < args.count else {
            fputs("missing value for \(a)\n", stderr)
            printUsage()
            exit(2)
        }
        if logPath != nil {
            fputs("--log-stream specified multiple times\n", stderr)
            printUsage()
            exit(2)
        }
        logPath = args[idx + 1]
        idx += 2
    case "--log-path-class":
        guard idx + 1 < args.count else {
            fputs("missing value for --log-path-class\n", stderr)
            printUsage()
            exit(2)
        }
        logPathClass = args[idx + 1]
        idx += 2
    case "--log-name":
        guard idx + 1 < args.count else {
            fputs("missing value for --log-name\n", stderr)
            printUsage()
            exit(2)
        }
        logName = args[idx + 1]
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

if logPredicate != nil && logPath == nil && logPathClass == nil {
    fputs("missing value for --log-stream or --log-path-class/--log-name (required when --log-predicate is set)\n", stderr)
    printUsage()
    exit(2)
}

if logPath != nil && logPathClass != nil {
    fputs("--log-path-class/--log-name cannot be combined with an explicit log path\n", stderr)
    printUsage()
    exit(2)
}

if (logPathClass != nil && logName == nil) || (logPathClass == nil && logName != nil) {
    fputs("--log-path-class and --log-name must be provided together\n", stderr)
    printUsage()
    exit(2)
}

if let logPathClass {
    guard isKnownPathClass(logPathClass) else {
        fputs("invalid --log-path-class (expected home|tmp|downloads|desktop|documents|app_support|caches)\n", stderr)
        printUsage()
        exit(2)
    }
}

if let logName, !isSinglePathComponent(logName) {
    fputs("invalid --log-name (must be a single path component)\n", stderr)
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

let resolvedLogPath: String? = {
    if let logPath {
        return logPath
    }
    if let logPathClass, let logName {
        return resolveContainerPath(bundleId: serviceName, pathClass: logPathClass, name: logName)
    }
    return nil
}()

if logPathClass != nil && resolvedLogPath == nil {
    fputs("failed to resolve --log-path-class/--log-name for service container\n", stderr)
    exit(2)
}

let logSpec = resolvedLogPath.map { LogCaptureSpec(path: $0, predicate_override: logPredicate) }

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

if waitMode == nil && waitPath == nil && waitPathClass != nil {
    // `--wait-path-class/--wait-name` is the ergonomic container-safe wait; default to FIFO.
    waitMode = "fifo"
    if waitCreate == nil {
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
} else if probeId == "fs_op_wait" {
    var i = 0
    while i + 1 < probeArgs.count {
        let flag = probeArgs[i]
        if flag == "--wait-fifo" || flag == "--wait-exists" {
            let mode = (flag == "--wait-fifo") ? "fifo" : "exists"
            let path = probeArgs[i + 1]
            fputs("[client] wait-ready mode=\(mode) wait_path=\(path)\n", stderr)
            break
        }
        i += 1
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

private var logStream: LogStreamHandle?
private var logStreamError: String?
private var logStreamPredicate: String?
if let spec = logSpec {
    let processNameHint = serviceNameHint(from: serviceName)
    let pidHint = connectionPidHint(connection)
    let predicate = spec.predicate_override ?? streamSandboxPredicate(processName: processNameHint, pid: pidHint)
    logStreamPredicate = predicate
    let (handle, err) = startLogStream(predicate: predicate)
    logStream = handle
    logStreamError = err
    Thread.sleep(forTimeInterval: 0.2)
}

let clientStarted = Date()
proxy.runProbe(requestData) { responseData in
    let clientEnded = Date()
    let rawJson = String(data: responseData, encoding: .utf8)
    do {
        var response = try decodeJSON(RunProbeResponse.self, from: responseData)
        exitCode = Int32(clamping: response.rc)

        var logCapturePredicate: String? = nil
        var logCaptureObservedLines: Int? = nil
        var logCaptureObservedDeny: Bool? = nil
        var logObserverStatus: String? = nil
        var logObserverError: String? = nil
        var logObserverPath: String? = nil
        var logObserverPredicate: String? = nil
        var logObserverStart: String? = nil
        var logObserverEnd: String? = nil
        var logObserverLast: String? = nil
        var logObserverObservedLines: Int? = nil
        var logObserverObservedDeny: Bool? = nil
        var logObserverDenyLines: [String]? = nil
        if let spec = logSpec {
            Thread.sleep(forTimeInterval: 0.2)
            let predicate = logStreamPredicate ?? spec.predicate_override ?? ""
            let summary = captureSandboxLogStream(
                spec: spec,
                stream: logStream,
                streamError: logStreamError,
                response: response,
                serviceName: serviceName,
                predicate: predicate
            )
            response.log_capture_status = summary.status
            response.log_capture_path = spec.path
            response.log_capture_error = summary.error
            logCapturePredicate = summary.predicate
            logCaptureObservedLines = summary.observedLines
            logCaptureObservedDeny = summary.observedDeny

            let observer = captureSandboxLogObserver(
                logPath: spec.path,
                response: response,
                serviceName: serviceName,
                predicateOverride: spec.predicate_override,
                planId: response.plan_id ?? planId,
                rowId: response.row_id ?? rowId,
                correlationId: response.correlation_id ?? correlationId,
                clientStarted: clientStarted,
                clientEnded: clientEnded
            )
            logObserverStatus = observer.status
            logObserverError = observer.error
            logObserverPath = observer.path
            logObserverPredicate = observer.predicate
            logObserverStart = observer.start
            logObserverEnd = observer.end
            logObserverLast = observer.last
            logObserverObservedLines = observer.observedLines
            logObserverObservedDeny = observer.observedDeny
            logObserverDenyLines = observer.denyLines

            let logStreamFound = summary.observedDeny == true
            let observerFound = observer.observedDeny == true
            let observerSucceeded = observer.status == "requested_written"
            if logStreamFound || observerFound {
                response.deny_evidence = "captured"
            } else if observerSucceeded || summary.denyEvidence == "not_found" {
                response.deny_evidence = "not_found"
            } else {
                response.deny_evidence = "log_error"
            }
        } else {
            response.log_capture_status = "not_requested"
            response.deny_evidence = "not_captured"
            logObserverStatus = "not_requested"
        }

        let data = ProbeData(
            plan_id: response.plan_id,
            row_id: response.row_id,
            correlation_id: response.correlation_id,
            probe_id: response.probe_id,
            argv: response.argv,
            expected_outcome: response.expected_outcome,
            service_bundle_id: response.service_bundle_id,
            service_name: response.service_name,
            service_version: response.service_version,
            service_build: response.service_build,
            started_at_iso8601: response.started_at_iso8601,
            ended_at_iso8601: response.ended_at_iso8601,
            thread_id: response.thread_id,
            details: response.details,
            layer_attribution: response.layer_attribution,
            sandbox_log_excerpt_ref: response.sandbox_log_excerpt_ref,
            log_capture_status: response.log_capture_status,
            log_capture_path: response.log_capture_path,
            log_capture_error: response.log_capture_error,
            log_capture_predicate: logCapturePredicate,
            log_capture_observed_lines: logCaptureObservedLines,
            log_capture_observed_deny: logCaptureObservedDeny,
            log_observer_status: logObserverStatus,
            log_observer_error: logObserverError,
            log_observer_path: logObserverPath,
            log_observer_predicate: logObserverPredicate,
            log_observer_start: logObserverStart,
            log_observer_end: logObserverEnd,
            log_observer_last: logObserverLast,
            log_observer_observed_lines: logObserverObservedLines,
            log_observer_observed_deny: logObserverObservedDeny,
            log_observer_deny_lines: logObserverDenyLines,
            deny_evidence: response.deny_evidence
        )

        let result = JsonResult(
            ok: response.rc == 0,
            rc: response.rc,
            exit_code: nil,
            normalized_outcome: response.normalized_outcome,
            errno: response.errno,
            error: response.error,
            stderr: response.stderr,
            stdout: response.stdout
        )

        let envelope = JsonEnvelope(
            kind: "probe_response",
            generated_at_unix_ms: UInt64(Date().timeIntervalSince1970 * 1000.0),
            result: result,
            data: data
        )

        do {
            let data = try encodeJSON(envelope)
            if let json = String(data: data, encoding: .utf8) {
                print(json)
            } else {
                fputs("failed to encode response JSON\n", stderr)
            }
        } catch {
            fputs("failed to encode response JSON: \(error)\n", stderr)
            if let rawJson {
                print(rawJson)
            }
        }
    } catch {
        let data = DecodeFailureData(raw_response: rawJson, decode_error: "\(error)")
        let result = JsonResult(
            ok: false,
            rc: nil,
            exit_code: 1,
            normalized_outcome: nil,
            errno: nil,
            error: "decode_failed",
            stderr: nil,
            stdout: nil
        )
        let envelope = JsonEnvelope(
            kind: "probe_response",
            generated_at_unix_ms: UInt64(Date().timeIntervalSince1970 * 1000.0),
            result: result,
            data: data
        )
        if let encoded = try? encodeJSON(envelope),
           let json = String(data: encoded, encoding: .utf8) {
            print(json)
        } else {
            fputs("failed to encode response JSON: \(error)\n", stderr)
            if let rawJson {
                print(rawJson)
            }
        }
        exitCode = 1
    }
    if let hold = holdOpenSeconds, hold > 0 {
        Thread.sleep(forTimeInterval: hold)
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
if let stream = logStream, stream.process.isRunning {
    _ = stopLogStream(stream)
}
connection.invalidate()
exit(exitCode)
