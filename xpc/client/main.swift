import Foundation
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "xpc-probe-client"
    fputs("usage: \(exe) [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] <xpc-service-bundle-id> <probe-id> [probe-args...]\n", stderr)
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

let request = RunProbeRequest(plan_id: nil, probe_id: probeId, argv: probeArgs, env_overrides: nil)
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
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
connection.invalidate()
exit(exitCode)
