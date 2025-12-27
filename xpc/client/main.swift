import Foundation

private func nowUnixMs() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000.0)
}

private final class LockedStdout {
    private let lock = NSLock()
    private let out = FileHandle.standardOutput

    func writeLine(_ line: String) {
        lock.lock()
        defer { lock.unlock() }
        if let data = (line + "\n").data(using: .utf8) {
            out.write(data)
        }
    }

    func writeDataLine(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        out.write(data)
        out.write(Data("\n".utf8))
    }
}

private final class SessionEventSink: NSObject, SessionEventSinkProtocol {
    private let stdout: LockedStdout

    init(stdout: LockedStdout) {
        self.stdout = stdout
    }

    func emitEvent(_ event: Data) {
        stdout.writeDataLine(event)
    }
}

private final class DiscardingSessionEventSink: NSObject, SessionEventSinkProtocol {
    func emitEvent(_ event: Data) {}
}

private func usage() -> String {
    """
    usage:
      xpc-probe-client run [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] <xpc-service-bundle-id> <probe-id> [probe-args...]
      xpc-probe-client session [--plan-id <id>] [--correlation-id <id>] [--wait <fifo:auto|fifo:/abs|exists:/abs>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--xpc-timeout-ms <n>] <xpc-service-bundle-id>

    notes:
      - session mode reads JSONL commands from stdin and emits JSONL to stdout.
      - valid stdin commands:
          {"command":"run_probe","probe_id":"capabilities_snapshot","argv":[],"row_id":"...","correlation_id":"..."}
          {"command":"keepalive"}
          {"command":"close_session"}
    """
}

private func die(_ message: String, code: Int32) -> Never {
    fputs(message + "\n", stderr)
    exit(code)
}

private struct XpcCallError: Error, CustomStringConvertible {
    let message: String

    var description: String {
        message
    }
}

private func xpcCall(
    connection: NSXPCConnection,
    timeoutMs: Int,
    invoke: (ProbeServiceProtocol, @escaping (Data) -> Void) -> Void
) -> Result<Data, XpcCallError> {
    let lock = NSLock()
    var done = false
    var replyData: Data?
    var replyError: Error?
    let sema = DispatchSemaphore(value: 0)

    guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
        lock.lock()
        defer { lock.unlock() }
        if done { return }
        done = true
        replyError = error
        sema.signal()
    }) as? ProbeServiceProtocol else {
        return .failure(XpcCallError(message: "failed to construct remote proxy (type mismatch)"))
    }

    invoke(proxy) { data in
        lock.lock()
        defer { lock.unlock() }
        if done { return }
        done = true
        replyData = data
        sema.signal()
    }

    let deadline = DispatchTime.now() + .milliseconds(timeoutMs)
    if sema.wait(timeout: deadline) == .timedOut {
        return .failure(XpcCallError(message: "xpc call timeout after \(timeoutMs)ms"))
    }

    lock.lock()
    let data = replyData
    let err = replyError
    lock.unlock()

    if let err {
        return .failure(XpcCallError(message: "xpc error: \(err)"))
    }
    if let data {
        return .success(data)
    }
    return .failure(XpcCallError(message: "xpc call failed (no reply and no error)"))
}

private func emitProbeResponseEnvelope(_ response: RunProbeResponse, stdout: LockedStdout) -> Int32 {
    let ok = response.rc == 0
    let result = JsonResult(
        ok: ok,
        rc: response.rc,
        exit_code: response.rc,
        normalized_outcome: response.normalized_outcome,
        errno: response.errno,
        error: response.error,
        stderr: response.stderr.isEmpty ? nil : response.stderr,
        stdout: response.stdout.isEmpty ? nil : response.stdout
    )
    let envelope = JsonEnvelope(
        kind: "probe_response",
        generated_at_unix_ms: nowUnixMs(),
        result: result,
        data: response
    )
    do {
        stdout.writeDataLine(try encodeJSON(envelope))
    } catch {
        fputs("encode failed: \(error)\n", stderr)
        let fallbackRc: Int32 = 2
        return fallbackRc
    }
    return Int32(max(0, min(255, response.rc)))
}

private func emitSessionErrorEnvelope(
    event: String,
    planId: String?,
    correlationId: String?,
    sessionToken: String?,
    pid: Int?,
    serviceBundleId: String?,
    serviceName: String?,
    waitMode: String?,
    waitPath: String?,
    error: String,
    stdout: LockedStdout
) {
    let data = XpcSessionErrorData(
        event: event,
        plan_id: planId,
        correlation_id: correlationId,
        session_token: sessionToken,
        pid: pid,
        service_bundle_id: serviceBundleId,
        service_name: serviceName,
        wait_mode: waitMode,
        wait_path: waitPath,
        error: error
    )
    let result = JsonResult(ok: false, rc: 1, exit_code: 1, normalized_outcome: "error", error: error)
    let envelope = JsonEnvelope(
        kind: "xpc_session_error",
        generated_at_unix_ms: nowUnixMs(),
        result: result,
        data: data
    )
    if let encoded = try? encodeJSON(envelope) {
        stdout.writeDataLine(encoded)
    }
}

private func parseInt(_ s: String, label: String) -> Int {
    guard let v = Int(s) else {
        die("invalid \(label): \(s)", code: 2)
    }
    return v
}

// MARK: - run

private func runOneShot(args: [String]) -> Never {
    let stdout = LockedStdout()

    var planId: String?
    var rowId: String?
    var correlationId: String?

    var idx = 0
    while idx < args.count {
        let arg = args[idx]
        if arg == "--" {
            idx += 1
            break
        }
        if !arg.hasPrefix("-") {
            break
        }
        switch arg {
        case "-h", "--help":
            die(usage(), code: 0)
        case "--plan-id":
            guard idx + 1 < args.count else { die("missing value for --plan-id", code: 2) }
            planId = args[idx + 1]
            idx += 2
        case "--row-id":
            guard idx + 1 < args.count else { die("missing value for --row-id", code: 2) }
            rowId = args[idx + 1]
            idx += 2
        case "--correlation-id":
            guard idx + 1 < args.count else { die("missing value for --correlation-id", code: 2) }
            correlationId = args[idx + 1]
            idx += 2
        default:
            die("unknown argument for run: \(arg)\n\n\(usage())", code: 2)
        }
    }

    guard idx + 1 < args.count else {
        die("missing required arguments for run\n\n\(usage())", code: 2)
    }
    let serviceBundleId = args[idx]
    let probeId = args[idx + 1]
    let probeArgv = Array(args.dropFirst(idx + 2))

    let sink = DiscardingSessionEventSink()
    let connection = NSXPCConnection(serviceName: serviceBundleId)
    connection.remoteObjectInterface = NSXPCInterface(with: ProbeServiceProtocol.self)
    connection.exportedInterface = NSXPCInterface(with: SessionEventSinkProtocol.self)
    connection.exportedObject = sink
    connection.resume()

    let timeoutMs = 30_000

    let openReq = SessionOpenRequest(plan_id: planId, correlation_id: correlationId, wait_spec: nil)
    let openReqData: Data
    do {
        openReqData = try encodeJSON(openReq)
    } catch {
        let response = RunProbeResponse(
            rc: 2,
            stdout: "",
            stderr: "failed to encode SessionOpenRequest: \(error)",
            normalized_outcome: "encode_failed",
            errno: nil,
            error: "\(error)",
            details: nil,
            layer_attribution: LayerAttribution(service_refusal: "client encode failed")
        )
        let code = emitProbeResponseEnvelope(response, stdout: stdout)
        exit(code)
    }

    let openReply = xpcCall(connection: connection, timeoutMs: timeoutMs) { proxy, reply in
        proxy.openSession(openReqData, withReply: reply)
    }

    let openResp: SessionOpenResponse
    switch openReply {
    case .failure(let err):
        let errMessage = err.message
        let response = RunProbeResponse(
            rc: 1,
            stdout: "",
            stderr: errMessage,
            normalized_outcome: "xpc_error",
            errno: nil,
            error: errMessage,
            details: ["service_bundle_id": serviceBundleId],
            layer_attribution: LayerAttribution(other: "xpc:openSession_failed")
        )
        let code = emitProbeResponseEnvelope(response, stdout: stdout)
        exit(code)
    case .success(let data):
        do {
            openResp = try decodeJSON(SessionOpenResponse.self, from: data)
        } catch {
            let response = RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "failed to decode SessionOpenResponse: \(error)",
                normalized_outcome: "decode_failed",
                errno: nil,
                error: "\(error)",
                details: ["service_bundle_id": serviceBundleId],
                layer_attribution: LayerAttribution(other: "xpc:openSession_decode_failed")
            )
            let code = emitProbeResponseEnvelope(response, stdout: stdout)
            exit(code)
        }
    }

    guard openResp.rc == 0, let sessionToken = openResp.session_token else {
        let err = openResp.error ?? "openSession failed"
        let response = RunProbeResponse(
            rc: openResp.rc == 0 ? 1 : openResp.rc,
            stdout: "",
            stderr: err,
            normalized_outcome: "open_session_failed",
            errno: nil,
            error: err,
            details: ["service_bundle_id": serviceBundleId],
            layer_attribution: LayerAttribution(other: "xpc:openSession_rc=\(openResp.rc)")
        )
        let code = emitProbeResponseEnvelope(response, stdout: stdout)
        exit(code)
    }

    let probeReq = RunProbeRequest(
        plan_id: planId,
        row_id: rowId,
        correlation_id: correlationId,
        probe_id: probeId,
        argv: probeArgv
    )
    let runReq = SessionRunProbeRequest(session_token: sessionToken, probe_request: probeReq)

    let runReqData: Data
    do {
        runReqData = try encodeJSON(runReq)
    } catch {
        let response = RunProbeResponse(
            rc: 2,
            stdout: "",
            stderr: "failed to encode SessionRunProbeRequest: \(error)",
            normalized_outcome: "encode_failed",
            errno: nil,
            error: "\(error)",
            details: ["service_bundle_id": serviceBundleId],
            layer_attribution: LayerAttribution(service_refusal: "client encode failed")
        )
        let code = emitProbeResponseEnvelope(response, stdout: stdout)
        exit(code)
    }

    let runReply = xpcCall(connection: connection, timeoutMs: timeoutMs) { proxy, reply in
        proxy.runProbeInSession(runReqData, withReply: reply)
    }

    let probeResp: RunProbeResponse
    switch runReply {
    case .failure(let err):
        let errMessage = err.message
        probeResp = RunProbeResponse(
            rc: 1,
            stdout: "",
            stderr: errMessage,
            normalized_outcome: "xpc_error",
            errno: nil,
            error: errMessage,
            details: ["service_bundle_id": serviceBundleId],
            layer_attribution: LayerAttribution(other: "xpc:runProbeInSession_failed")
        )
    case .success(let data):
        do {
            probeResp = try decodeJSON(RunProbeResponse.self, from: data)
        } catch {
            probeResp = RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "failed to decode RunProbeResponse: \(error)",
                normalized_outcome: "decode_failed",
                errno: nil,
                error: "\(error)",
                details: ["service_bundle_id": serviceBundleId],
                layer_attribution: LayerAttribution(other: "xpc:runProbeInSession_decode_failed")
            )
        }
    }

    // Best-effort close.
    let closeReq = SessionCloseRequest(session_token: sessionToken)
    if let closeReqData = try? encodeJSON(closeReq) {
        _ = xpcCall(connection: connection, timeoutMs: timeoutMs) { proxy, reply in
            proxy.closeSession(closeReqData, withReply: reply)
        }
    }
    connection.invalidate()

    let exitCode = emitProbeResponseEnvelope(probeResp, stdout: stdout)
    exit(exitCode)
}

// MARK: - session

private struct SessionCommand: Decodable {
    var command: String
    var plan_id: String?
    var row_id: String?
    var correlation_id: String?
    var probe_id: String?
    var argv: [String]?
}

private func runSession(args: [String]) -> Never {
    let stdout = LockedStdout()

    var planId: String?
    var correlationId: String?
    var waitSpec: String?
    var waitTimeoutMs: Int?
    var waitIntervalMs: Int?
    var xpcTimeoutMs: Int = 30_000

    var idx = 0
    while idx < args.count {
        let arg = args[idx]
        if arg == "--" {
            idx += 1
            break
        }
        if !arg.hasPrefix("-") {
            break
        }
        switch arg {
        case "-h", "--help":
            die(usage(), code: 0)
        case "--plan-id":
            guard idx + 1 < args.count else { die("missing value for --plan-id", code: 2) }
            planId = args[idx + 1]
            idx += 2
        case "--correlation-id":
            guard idx + 1 < args.count else { die("missing value for --correlation-id", code: 2) }
            correlationId = args[idx + 1]
            idx += 2
        case "--wait":
            guard idx + 1 < args.count else { die("missing value for --wait", code: 2) }
            waitSpec = args[idx + 1]
            idx += 2
        case "--wait-timeout-ms":
            guard idx + 1 < args.count else { die("missing value for --wait-timeout-ms", code: 2) }
            waitTimeoutMs = parseInt(args[idx + 1], label: "--wait-timeout-ms")
            idx += 2
        case "--wait-interval-ms":
            guard idx + 1 < args.count else { die("missing value for --wait-interval-ms", code: 2) }
            waitIntervalMs = parseInt(args[idx + 1], label: "--wait-interval-ms")
            idx += 2
        case "--xpc-timeout-ms":
            guard idx + 1 < args.count else { die("missing value for --xpc-timeout-ms", code: 2) }
            xpcTimeoutMs = parseInt(args[idx + 1], label: "--xpc-timeout-ms")
            idx += 2
        default:
            die("unknown argument for session: \(arg)\n\n\(usage())", code: 2)
        }
    }

    guard idx < args.count else {
        die("missing required argument: <xpc-service-bundle-id>\n\n\(usage())", code: 2)
    }
    let serviceBundleId = args[idx]
    if idx + 1 != args.count {
        die("session takes exactly one positional argument: <xpc-service-bundle-id>\n\n\(usage())", code: 2)
    }

    let connection = NSXPCConnection(serviceName: serviceBundleId)
    connection.remoteObjectInterface = NSXPCInterface(with: ProbeServiceProtocol.self)

    let sink = SessionEventSink(stdout: stdout)
    connection.exportedInterface = NSXPCInterface(with: SessionEventSinkProtocol.self)
    connection.exportedObject = sink

    connection.interruptionHandler = {
        emitSessionErrorEnvelope(
            event: "connection_interrupted",
            planId: planId,
            correlationId: correlationId,
            sessionToken: nil,
            pid: nil,
            serviceBundleId: serviceBundleId,
            serviceName: nil,
            waitMode: nil,
            waitPath: nil,
            error: "xpc connection interrupted",
            stdout: stdout
        )
    }
    connection.invalidationHandler = {
        emitSessionErrorEnvelope(
            event: "connection_invalidated",
            planId: planId,
            correlationId: correlationId,
            sessionToken: nil,
            pid: nil,
            serviceBundleId: serviceBundleId,
            serviceName: nil,
            waitMode: nil,
            waitPath: nil,
            error: "xpc connection invalidated",
            stdout: stdout
        )
    }

    connection.resume()

    let wait: WaitSpec? = {
        guard let waitSpec else { return nil }
        return WaitSpec(spec: waitSpec, timeout_ms: waitTimeoutMs, interval_ms: waitIntervalMs)
    }()

    let openReq = SessionOpenRequest(plan_id: planId, correlation_id: correlationId, wait_spec: wait)
    let openReqData: Data
    do {
        openReqData = try encodeJSON(openReq)
    } catch {
        emitSessionErrorEnvelope(
            event: "client_encode_failed",
            planId: planId,
            correlationId: correlationId,
            sessionToken: nil,
            pid: nil,
            serviceBundleId: serviceBundleId,
            serviceName: nil,
            waitMode: nil,
            waitPath: nil,
            error: "failed to encode SessionOpenRequest: \(error)",
            stdout: stdout
        )
        exit(2)
    }

    let openReply = xpcCall(connection: connection, timeoutMs: xpcTimeoutMs) { proxy, reply in
        proxy.openSession(openReqData, withReply: reply)
    }

    let openResp: SessionOpenResponse
    switch openReply {
    case .failure(let err):
        let errMessage = err.message
        emitSessionErrorEnvelope(
            event: "open_session_failed",
            planId: planId,
            correlationId: correlationId,
            sessionToken: nil,
            pid: nil,
            serviceBundleId: serviceBundleId,
            serviceName: nil,
            waitMode: nil,
            waitPath: nil,
            error: errMessage,
            stdout: stdout
        )
        exit(1)
    case .success(let data):
        do {
            openResp = try decodeJSON(SessionOpenResponse.self, from: data)
        } catch {
            emitSessionErrorEnvelope(
                event: "open_session_decode_failed",
                planId: planId,
                correlationId: correlationId,
                sessionToken: nil,
                pid: nil,
                serviceBundleId: serviceBundleId,
                serviceName: nil,
                waitMode: nil,
                waitPath: nil,
                error: "failed to decode SessionOpenResponse: \(error)",
                stdout: stdout
            )
            exit(1)
        }
    }

    guard openResp.rc == 0, let sessionToken = openResp.session_token else {
        let err = openResp.error ?? "openSession failed"
        emitSessionErrorEnvelope(
            event: "open_session_rc_nonzero",
            planId: planId,
            correlationId: correlationId,
            sessionToken: openResp.session_token,
            pid: openResp.pid,
            serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
            serviceName: openResp.service_name,
            waitMode: openResp.wait_mode,
            waitPath: openResp.wait_path,
            error: err,
            stdout: stdout
        )
        exit(Int32(max(1, min(255, openResp.rc))))
    }

    func closeAndExit(code: Int32) -> Never {
        let closeReq = SessionCloseRequest(session_token: sessionToken)
        if let closeReqData = try? encodeJSON(closeReq) {
            _ = xpcCall(connection: connection, timeoutMs: xpcTimeoutMs) { proxy, reply in
                proxy.closeSession(closeReqData, withReply: reply)
            }
        }
        connection.invalidate()
        exit(code)
    }

    while let line = readLine() {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            continue
        }

        let cmd: SessionCommand
        do {
            cmd = try JSONDecoder().decode(SessionCommand.self, from: Data(trimmed.utf8))
        } catch {
            emitSessionErrorEnvelope(
                event: "bad_command",
                planId: planId,
                correlationId: correlationId,
                sessionToken: sessionToken,
                pid: openResp.pid,
                serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                serviceName: openResp.service_name,
                waitMode: openResp.wait_mode,
                waitPath: openResp.wait_path,
                error: "failed to decode command JSON: \(error)",
                stdout: stdout
            )
            continue
        }

        switch cmd.command {
        case "keepalive":
            let keepReq = SessionKeepaliveRequest(session_token: sessionToken)
            guard let keepReqData = try? encodeJSON(keepReq) else {
                emitSessionErrorEnvelope(
                    event: "client_encode_failed",
                    planId: planId,
                    correlationId: correlationId,
                    sessionToken: sessionToken,
                    pid: openResp.pid,
                    serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                    serviceName: openResp.service_name,
                    waitMode: openResp.wait_mode,
                    waitPath: openResp.wait_path,
                    error: "failed to encode keepalive request",
                    stdout: stdout
                )
                continue
            }
            let reply = xpcCall(connection: connection, timeoutMs: xpcTimeoutMs) { proxy, reply in
                proxy.keepaliveSession(keepReqData, withReply: reply)
            }
            switch reply {
            case .failure(let err):
                let errMessage = err.message
                emitSessionErrorEnvelope(
                    event: "keepalive_failed",
                    planId: planId,
                    correlationId: correlationId,
                    sessionToken: sessionToken,
                    pid: openResp.pid,
                    serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                    serviceName: openResp.service_name,
                    waitMode: openResp.wait_mode,
                    waitPath: openResp.wait_path,
                    error: errMessage,
                    stdout: stdout
                )
            case .success(let data):
                if let decoded = try? decodeJSON(SessionControlResponse.self, from: data), decoded.rc != 0 {
                    emitSessionErrorEnvelope(
                        event: "keepalive_rc_nonzero",
                        planId: planId,
                        correlationId: correlationId,
                        sessionToken: sessionToken,
                        pid: openResp.pid,
                        serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                        serviceName: openResp.service_name,
                        waitMode: openResp.wait_mode,
                        waitPath: openResp.wait_path,
                        error: decoded.error ?? "keepalive failed",
                        stdout: stdout
                    )
                }
            }

        case "run_probe":
            guard let probeId = cmd.probe_id, !probeId.isEmpty else {
                emitSessionErrorEnvelope(
                    event: "bad_command",
                    planId: planId,
                    correlationId: correlationId,
                    sessionToken: sessionToken,
                    pid: openResp.pid,
                    serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                    serviceName: openResp.service_name,
                    waitMode: openResp.wait_mode,
                    waitPath: openResp.wait_path,
                    error: "missing command.probe_id",
                    stdout: stdout
                )
                continue
            }
            let req = RunProbeRequest(
                plan_id: cmd.plan_id ?? planId,
                row_id: cmd.row_id,
                correlation_id: cmd.correlation_id ?? correlationId,
                probe_id: probeId,
                argv: cmd.argv ?? []
            )
            let runReq = SessionRunProbeRequest(session_token: sessionToken, probe_request: req)
            guard let runReqData = try? encodeJSON(runReq) else {
                emitSessionErrorEnvelope(
                    event: "client_encode_failed",
                    planId: planId,
                    correlationId: correlationId,
                    sessionToken: sessionToken,
                    pid: openResp.pid,
                    serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                    serviceName: openResp.service_name,
                    waitMode: openResp.wait_mode,
                    waitPath: openResp.wait_path,
                    error: "failed to encode run_probe request",
                    stdout: stdout
                )
                continue
            }
            let reply = xpcCall(connection: connection, timeoutMs: xpcTimeoutMs) { proxy, reply in
                proxy.runProbeInSession(runReqData, withReply: reply)
            }
            switch reply {
            case .failure(let err):
                let errMessage = err.message
                emitSessionErrorEnvelope(
                    event: "run_probe_failed",
                    planId: planId,
                    correlationId: correlationId,
                    sessionToken: sessionToken,
                    pid: openResp.pid,
                    serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                    serviceName: openResp.service_name,
                    waitMode: openResp.wait_mode,
                    waitPath: openResp.wait_path,
                    error: errMessage,
                    stdout: stdout
                )
            case .success(let data):
                if let decoded = try? decodeJSON(RunProbeResponse.self, from: data) {
                    _ = emitProbeResponseEnvelope(decoded, stdout: stdout)
                } else {
                    emitSessionErrorEnvelope(
                        event: "run_probe_decode_failed",
                        planId: planId,
                        correlationId: correlationId,
                        sessionToken: sessionToken,
                        pid: openResp.pid,
                        serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                        serviceName: openResp.service_name,
                        waitMode: openResp.wait_mode,
                        waitPath: openResp.wait_path,
                        error: "failed to decode RunProbeResponse",
                        stdout: stdout
                    )
                }
            }

        case "close_session":
            closeAndExit(code: 0)

        default:
            emitSessionErrorEnvelope(
                event: "bad_command",
                planId: planId,
                correlationId: correlationId,
                sessionToken: sessionToken,
                pid: openResp.pid,
                serviceBundleId: openResp.service_bundle_id ?? serviceBundleId,
                serviceName: openResp.service_name,
                waitMode: openResp.wait_mode,
                waitPath: openResp.wait_path,
                error: "unknown command: \(cmd.command)",
                stdout: stdout
            )
        }
    }

    closeAndExit(code: 0)
}

// MARK: - entrypoint

let argv = Array(CommandLine.arguments.dropFirst())
if argv.isEmpty {
    die(usage(), code: 2)
}

switch argv[0] {
case "-h", "--help", "help":
    die(usage(), code: 0)
case "run":
    runOneShot(args: Array(argv.dropFirst()))
case "session":
    runSession(args: Array(argv.dropFirst()))
default:
    die("unknown subcommand: \(argv[0])\n\n\(usage())", code: 2)
}
