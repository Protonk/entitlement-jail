import Foundation
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "xpc-probe-client"
    fputs("usage: \(exe) <xpc-service-bundle-id> <probe-id> [probe-args...]\n", stderr)
}

if ProcessInfo.processInfo.environment["EJ_XPC_CLIENT_DEBUG"] == "1" {
    let exePath = CommandLine.arguments.first ?? "<unknown>"
    let bundlePath = Bundle.main.bundleURL.path
    let bundleId = Bundle.main.bundleIdentifier ?? "<nil>"
    fputs("debug: exe=\(exePath)\n", stderr)
    fputs("debug: Bundle.main.bundlePath=\(bundlePath)\n", stderr)
    fputs("debug: Bundle.main.bundleIdentifier=\(bundleId)\n", stderr)
}

let args = CommandLine.arguments
guard args.count >= 3 else {
    printUsage()
    exit(2)
}

let serviceName = args[1]
let probeId = args[2]
let probeArgs = Array(args.dropFirst(3))

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

proxy.runProbe(requestData) { responseData in
    if let json = String(data: responseData, encoding: .utf8) {
        print(json)
    } else {
        fputs("service returned non-utf8 response\n", stderr)
    }

    do {
        let response = try decodeJSON(RunProbeResponse.self, from: responseData)
        exitCode = Int32(clamping: response.rc)
    } catch {
        fputs("failed to decode response JSON: \(error)\n", stderr)
        exitCode = 1
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
connection.invalidate()
exit(exitCode)
